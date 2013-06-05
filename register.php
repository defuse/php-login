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
require_once('security/Filter.php');

if(
    !isset($_POST['username']) || !isset($_POST['email'])  || !isset($_POST['password']) || 
    !isset($_POST['passwordverify']) || !isset($_POST['hashed']) || !isset($_POST['allowreset'])
   )
{
    die('whut?'); //TODO: 404
}

$username = $_POST['username'];
$email = $_POST['email'];
$password = $_POST['password'];
$passwordverify = $_POST['passwordverify'];
$hashed = $_POST['hashed'];
$allowreset = ($_POST['allowreset'] == "true") ? TRUE : FALSE;

$good = true;

if($hashed != "1")
{
    if($password != $passwordverify)
    {
        $good = false;
        //TODO: Implement code to handle passwords that don't conform to the password policy.
        die("Passwords do not match.");
    }
    else if(!Filter::ConformsToPasswordPolicy($password))
    {
        $good = false;
        //TODO: Implement code to handle passwords that don't conform to the password policy.
        die("Sorry, your password doesn't conform to the password policy.");
    }

    if($good && ENABLE_CLIENTSIDE_HASH && ENABLE_SERVERSIDE_EMULATE)
    {
        $password = Crypto::EmulateClientSideHash($password, $username);
    }
    else if($good && ENABLE_CLIENTSIDE_HASH && !ENABLE_SERVERSIDE_EMULATE)
    {
        $good = false;
        //TODO: Replace this with what you want to do when you disable server-side client hash emulation.
        die("Sorry we don't have enough computational resources to hash your password, please enable JavaScript.");
    }
}

if($good)
{
    if(!Filter::IsValidUsername($username))
    {
        die("Username contains invalid characters or is too long.");
    }
    elseif(!Filter::IsValidEmail($email))
    {
        die("Email contains invalid characters or is not well-formed.");
    }
    elseif(!Accounts::CreateAccount($username, $email, $password, $allowreset))
    {
        die("Sorry, that username is already taken.");
    }

    if(REQUIRE_EMAIL_VALIDATION)
    {
        header('Location: validation.php?fuser=' . urlencode($username));
        die();
    }
}

?>
