<?php
require_once('inc/accounts.php');
require_once('security/Filter.php');
require_once('inc/PasswordReset.php');

include('ui/page_top.php');

$token_report = false;
if(isset($_POST['requesttoken']))
{
    PasswordReset::SendPasswordResetEmail($_POST['username']);
    $token_report = true;
}

?>
<h2>Step 1: Request a password reset token</h2>
<?php
    if($token_report)
    {
        //Vague on purpose
        echo "<p><b>If you entered a valid username, and your account has password 
                reset over email enabled then a password reset token has just been
                sent to the email address associated with your account.</b></p>";
    }
?>
<form action="reset.php" method="post">
    Username: <input type="text" name="username" value="" />
    <input type="submit" name="requesttoken" value="Request Reset Token" />
</form>

<br />
<h2>Step 2: Use the token to reset your password</h2>

<?php
if(isset($_POST['reset']))
{
    $token = $_POST['token'];
    $username = $_POST['username'];
    $new = $_POST['newp'];
    $hashed = $_POST['hashed'];

    $good = true;
    if($hashed != "1")
    {
        $newverify = $_POST['newverify'];
        if($new != $newverify)
        {
            $good = false;
            echo "<strong>Passwords do not match.<strong>";
        }
        else if(!Filter::ConformsToPasswordPolicy($new))
        {
            $good = false;
            echo "<strong>Sorry, your password doesn't conform to the password policy.</strong>";
        }

        if($good && ENABLE_CLIENTSIDE_HASH && ENABLE_SERVERSIDE_EMULATE)
        {
            $new = Crypto::EmulateClientSideHash($new, $username); 
        }
        else if($good && ENABLE_CLIENTSIDE_HASH && !ENABLE_SERVERSIDE_EMULATE)
        {
            $good = false;
            die("Sorry we don't have enough computational resources to hash your password, please enable JavaScript.");
        }
    }

    if($good)
    {
        if(PasswordReset::UserPasswordReset($token, $username, $new))
        {
            echo "<strong>Your password has been reset.</strong>";
        }
        else
        {
            // Vague on purpose
            echo "<strong>Could not reset your password. Either you provided an invalid reset token or an invalid username.</strong>";
        }
    }
}
?>
<form name="resetform" action="reset.php" method="post">
<table>
    <tr><td>Username:</td><td><input type="text" name="username" value="" /></td></tr>
    <tr><td>Token:</td><td><input type="text" name="token" value="" /></td></tr>
    <tr><td>New Password:</td><td><input type="password" name="newp" value="" /></td></tr>
    <tr><td>Repeat New Password: &nbsp;</td><td><input type="password" name="newverify" value="" /></td></tr>
</table>
<input type="hidden" name="hashed" value="0" /><br />
<?php
if(ENABLE_CLIENTSIDE_HASH)
{
?>
    <!-- Fall back to server side hashing when JavaScript isn't enabled -->
    <noscript>
        <div style="font-weight: bold; padding: 5px; border: solid black 1px; background-color: #00FFFF">
            WARNING: You have JavaScript disabled. Your password will be sent to the server without being hashed. It will still get hashed server-side, but it is best to enable JavaScript for this website so that it will get hashed before being sent to the server.
        </div>
        <input type="submit" name="reset" value="Reset Password" />
    </noscript>
    </form>

    <form name="jsresetform" action="reset.php" method="post">
    <input type="hidden" name="hashed" value="1" />
    <input type="hidden" name="username" value="" />
    <input type="hidden" name="token" value="" />
    <input type="hidden" name="newp" value="" />
    <input type="hidden" name="reset" value="Reset Password" />
    <input style="display:none" type="button" id="resetbutton" onclick="submitReset();" value="Reset Password" />
    <!-- Dummy button -->
    <input style="display:none" type="submit" name="dummybutton" value="dummybutton" />
    </form>
<?
}
else
{
?>
    <input type="submit" name="change" value="Change Password" />
<?
}
?>
</form>

<script type="text/javascript" src="js/sjcl.js"></script>
<script type="text/javascript" src="js/passwords.js.php"></script>
<script type="text/javascript">
enableJSOnly();
function enableJSOnly()
{
    document.getElementById("resetbutton").style.display='block';
}

function submitReset()
{
    var username = document.resetform.username.value;
    var token = document.resetform.token.value;
    var newp = document.resetform.newp.value;
    var newverify = document.resetform.newverify.value;

    if(newp != newverify)
    {
        alert('Passwords do not match!');
        return;
    }

    if(!conformsToPolicy(newp))
    {
        alert("Sorry, your password doesn't meet the required password policy");
        return;
    }

    var newhash = computeHash(username, newp);

    document.jsresetform.username.value = username;
    document.jsresetform.token.value = token;
    document.jsresetform.newp.value = newhash;
    document.jsresetform.submit();
}
</script>
<?php
include('ui/page_end.php');
?>
