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
require_once('inc/security.conf.php');
require_once('security/Crypto.php');
require_once('inc/accounts.php');
require_once('inc/UserLogin.php');
require_once('inc/EmailValidation.php');
require_once('inc/UserLockout.php');
require_once('security/Escape.php');

if(!isset($_POST['username']) || !isset($_POST['password']) ||
   !isset($_POST['hashed']) || !isset($_POST['sessiontime']) ||
   !isset($_POST['eoc'])
   )
{
    die();
}

$username = $_POST['username'];
$password = $_POST['password'];
$hashed = $_POST['hashed'];
$sessiontime = (int)$_POST['sessiontime'];
//TODO: Test this
$expireOnClose = ($_POST['eoc'] == "true") ? TRUE : FALSE;

$lockbypass = null;
if(isset($_COOKIE['_lockbypass']))
    $lockbypass = $_COOKIE['_lockbypass'];


if(ENABLE_CLIENTSIDE_HASH && $hashed != "1")
{
    if(ENABLE_SERVERSIDE_EMULATE)
    {
        $password = Crypto::EmulateClientSideHash($password, $username);
    }
    else
    {
        //TODO: Replace this with what you want to do when you disable server-side client hash emulation.
        die("Sorry we don't have enough computational resources to hash your password, please enable JavaScript.");
    }
}

if($sessiontime <= MAX_SESSION_LIFE && $sessiontime >= MIN_SESSION_LIFE)
{
    //TODO: **** attacker can extract usernames using the lockout mechanism ***
    if(UserLogin::CookieLogin($username, $password, $sessiontime, $lockbypass, $expireOnClose))
    {
        header('Location: profile.php');
    }
    elseif(UserLockout::IsLockedOut($username)) // Returns TRUE if $username doesn't exist.
    {
        die('Locked out. Click <a href="sendunlock.php?username=' . 
        Escape::html($username) . 
        '" >here</a> to send a temporary unlock code to your email.'); 
        //TODO: tell them how long until they aren't locked out anymore
    }
    // This is above the validation check to stop bad guys from being able to enumerate unvalidated accounts.
    elseif(!Accounts::CheckPassword($username, $password))
    {
        die('Wrong username or password!'); //TODO: Tell them how many times left before they get locked out.
    }
    elseif(!EmailValidation::IsUserValidated($username))
    {
        header('Location: validation.php?resend=' . urlencode($username));
        die();
    }
    else
    {
        die('Could not log in.');
    }
}
else
{
    die('hacker');
}


?>
