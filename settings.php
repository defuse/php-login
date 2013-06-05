<?php
/*
 * This code is hereby placed into the public domain by its author Taylor 
 * Hornby. It may be freely used for any purpose whatsoever.
 *
 * Developer's Contact Information:
 * WWW:     https://defuse.ca/
 * EMAIL:   <fillmein>
 * 
 * ***DISCLAIMER***
 *
 * ALL PUBLIC DOMAIN MATERIAL IS OFFERED AS-IS. NO REPRESENTATIONS OR
 * WARRANTIES OF ANY KIND ARE MADE CONCERNING THE MATERIALS, EXPRESS,
 * IMPLIED, STATUTORY OR OTHERWISE, INCLUDING, WITHOUT LIMITATION,
 * WARRANTIES OF TITLE, MERCHANTIBILITY, FITNESS FOR A PARTICULAR PURPOSE,
 * NONINFRINGEMENT, OR THE ABSENCE OF LATENT OR OTHER DEFECTS, ACCURACY, OR
 * THE PRESENCE OF ABSENCE OF ERRORS, WHETHER OR NOT DISCOVERABLE.
 * 
 * Limitation on Liability.
 * 
 * IN NO EVENT WILL THE AUTHOR(S), PUBLISHER(S), OR PRESENTER(S) OF ANY
 * PUBLIC DOMAIN MATERIAL BE LIABLE TO YOU ON ANY LEGAL THEORY FOR ANY
 * SPECIAL, INCIDENTAL, CONSEQUENTIAL, PUNITIVE OR EXEMPLARY DAMAGES
 * ARISING OUT OF THIS LICENSE OR THE USE OF THE WORK, EVEN IF THE
 * AUTHOR(S), PUBLISHER(S), OR PRESENTER(S) HAVE BEEN ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGES.
*/
require_once('inc/accounts.php');
require_once('inc/security.conf.php');
require_once('security/Filter.php');
require_once('inc/UserLockout.php');
require_once('inc/PasswordReset.php');
require_once('inc/Escape.php');

include('inc/require_login.php');
include('ui/page_top.php');

?>
<h2>General Settings</h2>

<?php
if(isset($_POST['savegeneral']))
{
    $reset_allowed = isset($_POST['allowreset']) && $_POST['allowreset'] == "true";
    $lock_enabled = isset($_POST['allowlock']) && $_POST['allowlock'] == "true";
    $lock_bypass_enabled = isset($_POST['allowlockbypass']) && $_POST['allowlockbypass'] == "true";

    PasswordReset::SetResetEnabled($USER->username(), $reset_allowed);
    UserLockout::SetLockEnabled($USER->username(), $lock_enabled);
    UserLockout::SetLockBypassEnabled($USER->username(), $lock_bypass_enabled);
    echo "<p><b>Settings saved.</b></p>";
}
    $reset_allowed = PasswordReset::IsPasswordResetAllowed($USER->username());
    $lock_enabled = UserLockout::IsLockEnabled($USER->username());
    $lock_bypass_enabled = UserLockout::IsLockBypassEnabled($USER->username());
?>
<form name="settingsform" action="settings.php" method="post">
    <input type="checkbox" name="allowlock" value="true"
        <?php if($lock_enabled) echo 'checked="checked"'; ?>
    > Lock my account when it looks like someone is trying to break in.
    <br />
    <input type="checkbox" name="allowlockbypass" value="true" 
        <?php if($lock_bypass_enabled) echo 'checked="checked"'; ?>
    > Allow me to login even when my account is locked by confirming my email.
    <br />
    <input type="checkbox" name="allowreset" value="true" 
        <?php if($reset_allowed) echo 'checked="checked"';?>
    > Allow me to reset my password over email.
    <br />
    <input type="submit" name="savegeneral" value="Save Settings" />
</form>

<h2>Change Password</h2>

<?php
if(isset($_POST['change']))
{
    $old = $_POST['old'];
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
            $old = Crypto::EmulateClientSideHash($old, $USER->username()); 
            $new = Crypto::EmulateClientSideHash($new, $USER->username()); 
        }
        else if($good && ENABLE_CLIENTSIDE_HASH && !ENABLE_SERVERSIDE_EMULATE)
        {
            $good = false;
            die("Sorry we don't have enough computational resources to hash your password, please enable JavaScript.");
        }
    }

    if($good)
    {
        if(UserLockout::IsLockedOut($USER->username()))
        {
            echo "<strong>Sorry, you have been locked out.</strong>";
        }
        elseif(Accounts::ChangePassword($USER->username(), $old, $new))
        {
            echo "<strong>Your password has been changed.</strong>";
        }
        else
        {
            echo "<strong>Wrong password.</strong>";
        }
    }
}
?>


<form name="changeform" action="settings.php" method="post">
<table>
    <tr><td>Old Password:</td><td><input type="password" name="old" value="" /></td></tr>
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
        <input type="submit" name="change" value="Change Password" />
    </noscript>
    </form>

    <form name="jschangeform" action="settings.php" method="post">
    <input type="hidden" name="hashed" value="1" />
    <input type="hidden" name="old" value="" />
    <input type="hidden" name="newp" value="" />
    <input type="hidden" name="change" value="Change Password" />
    <input style="display:none" type="button" id="changebutton" onclick="submitChange();" value="Change Password" />
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
    document.getElementById("changebutton").style.display='block';
}

function submitChange()
{
    var username = "<?php echo Escape::JavaScriptStringLiteral($USER->username()); ?>";
    var old = document.changeform.old.value;
    var newp = document.changeform.newp.value;
    var newverify = document.changeform.newverify.value;

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

    var oldhash = computeHash(username, old);
    var newhash = computeHash(username, newp);

    document.jschangeform.old.value = oldhash;
    document.jschangeform.newp.value = newhash;
    document.jschangeform.submit();
}
</script>
<?php
    include('ui/page_end.php');
?>
