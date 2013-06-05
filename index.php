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
    // TODO: capture enter key press in login and register box with JS
    require_once('inc/security.conf.php');
    require_once('security/Escape.php');
    include('ui/page_top.php');
?>
<script type="text/javascript" src="js/sjcl.js"></script>

<p>
    This is a demo of <a href="https://defuse.ca/">Defuse Cyber-Security's</a> secure user account system for PHP.
    The system was designed from the ground up with security in mind. Here are some notable features:
</p>

<ul>
    <li>User passwords are hashed client-side and server-side.</li>
    <li>User data is encrypted with a key derived from the user's password.</li>
    <li>Session data encrypted.</li>
    <li>Uses well-designed cryptography wherever possible to enforce security attributes.</li>
    <li>Uses parameterized SQL queries to eliminate SQL injection attacks.</li>
</ul>

<p>
    Feel free to create an account and use the system.
</p>

<!-- Login Form -->
<h2>Login</h2>
<form name="loginform" action="login.php" method="post">
    <table>
    <tr>
        <td>Username:</td>
        <td>
            <input type="text" name="username" value="" 
            maxlength="<?php echo Escape::html(MAX_USERNAME_LENGTH); ?>"/>
        </td>
    </tr>
    <tr>
        <td>
            Password:</td><td><input type="password" name="password" value="" />
            <a href="reset.php">Forgot your password?</a>
        </td>
    </tr>
    <tr><td>Stay logged in for:&nbsp;&nbsp;</td>
    <td>
    <select name="sessiontime">
        <option value="3600">1 Hour</option>
        <option value="21600" selected="selected">6 Hours</option>
        <option value="86400">24 Hours</option>
        <option value="2592000">Forever</option>
    </select>
    </td></tr>
    <tr><td>&nbsp;</td><td><input type="checkbox" name="eoc" value="true" checked="checked" /> Log me out when I close my browser.</td></tr>
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
            <input type="submit" name="login" value="Login" />
        </noscript>
        </form>
        <!-- Use a separate form for the hashed login - so we're compatible with web browser password managers -->
        <form name="jsloginform" action="login.php" method="post">
        <input type="hidden" name="hashed" value="1" />
        <input type="hidden" name="username" value="" />
        <input type="hidden" name="sessiontime" value="" />
        <input type="hidden" name="eoc" value="" />
        <input type="hidden" name="password" value="" />
        <!-- This button is displayed only when JavaScript is enabled -->
        <input style="display:none" type="button" id="loginbutton" onclick="submitLogin();" value="Login" />

        <!-- This is a dummy submit button to stop FireFox from creating a default submit button -->
        <input style="display:none" type="submit" name="dummybutton" value="dummybutton" />
    <?
    }
    else
    {
    ?>
        <input type="submit" name="login" value="Login" />
    <?
    }
    ?>
</form> <!-- either loginform or jsloginform -->

<!-- Registration Form -->
<h2>Register</h2>
<form name="registerform" action="register.php" method="post">
    <table>
    <tr>
        <td>Username:</td>
        <td>
            <input type="text" name="username" value="" 
            maxlength="<?php echo Escape::html(MAX_USERNAME_LENGTH); ?>"/>
        </td>
    </tr>
    <tr>
        <td>Email:</td>
        <td>
            <input type="text" name="email" value="" 
            maxlength="<?php echo Escape::html(MAX_EMAIL_LENGTH); ?>" />
        </td>
    </tr>
    <tr><td>Password:</td><td><input type="password" name="password" value="" /></td></tr>
    <tr><td>Verify Password:&nbsp;&nbsp;</td><td><input type="password" name="passwordverify" value="" /></td></tr>
    <tr><td>&nbsp;</td><td><input type="checkbox" name="allowreset" value="true" checked="checked" />Let me reset my password via email if I forget it.</td></tr>
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
            <input type="submit" name="register" value="Create Account" />
        </noscript>
        </form>
        <!-- Use a separate form for the hashed login - so we're compatible with web browser password managers -->
        <form name="jsregisterform" action="register.php" method="post">
        <input type="hidden" name="hashed" value="1" />
        <input type="hidden" name="username" value="" />
        <input type="hidden" name="email" value="" />
        <input type="hidden" name="password" value="" />
        <input type="hidden" name="passwordverify" value="" /><br />
        <input type="hidden" name="allowreset" value="" /><br />
        <!-- This button is displayed only when JavaScript is enabled -->
        <input style="display:none" type="button" id="registerbutton" onclick="submitRegister();" value="Create Account" />
        <!-- This is a dummy submit button to stop FireFox from creating a default submit button -->
        <input style="display:none" type="submit" name="dummybutton" value="dummybutton" />
    <?
    }
    else
    {
    ?>
        <input type="submit" name="register" value="Create Account" />
    <?
    }
    ?>
</form> <!-- either registerform or jsregisterform -->

<!-- Client-side hashing scripts -->
<script type="text/javascript" src="js/passwords.js.php"></script>
<script type="text/javascript">
enableJSOnly();

function enableJSOnly()
{
    document.getElementById("loginbutton").style.display='block';
    document.getElementById("registerbutton").style.display='block';
}


function submitLogin()
{
    var username = document.loginform.username.value;
    var password = document.loginform.password.value;
    var sessiontime = document.loginform.sessiontime.value;
    var hash = computeHash(username, password);

    if(document.loginform.eoc.checked)
    {
        document.jsloginform.eoc.value = "true";
    }
    else
    {
        document.jsloginform.eoc.value = "";
    }

    document.jsloginform.username.value = username;
    document.jsloginform.password.value = hash;
    document.jsloginform.sessiontime.value = sessiontime;
    document.jsloginform.submit();
}

function submitRegister()
{
    var username = document.registerform.username.value;
    var email = document.registerform.email.value;
    var password = document.registerform.password.value;
    var passwordVerify = document.registerform.passwordverify.value;

    if(password != passwordVerify)
    {
        alert("Your passwords don't match. Try again please.");
        return;
    }

    if(!conformsToPolicy(password))
    {
        alert("Sorry, your password doesn't meet the required password policy.");
        return;
    }

    var hash = computeHash(username, password);

    if(document.registerform.allowreset.checked)
    {
        document.jsregisterform.allowreset.value = "true";
    }
    else
    {
        document.jsregisterform.allowreset.value = "";
    }
    
    document.jsregisterform.username.value = username;
    document.jsregisterform.email.value = email;
    document.jsregisterform.password.value = hash;
    document.jsregisterform.passwordverify.value = hash;
    document.jsregisterform.submit();
}
</script>
<?php
    include('ui/page_end.php');
?>
