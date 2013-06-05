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
require_once('inc/EmailValidation.php');
require_once('inc/security.conf.php');
require_once('security/Escape.php');

if(!REQUIRE_EMAIL_VALIDATION)
{
    //TODO: 404
}

//TODO: Make some UI change indicating the mail was resent when they click resend
include('ui/page_top.php');

if(isset($_GET['resend']))
{
    $user = $_GET['resend'];
    $email = Accounts::GetUserEmail($user);
    if($email !== FALSE)
    {
        EmailValidation::SendValidationEmail($user, $email);
    }
    header('Location: validation.php?fuser=' . urlencode($user));
    die();
}

if(isset($_GET['fuser']))
{
    $safe_fuser = Escape::html($_GET['fuser']);
?>
    <h2>Account Validation</h2>
    <p>You have just been sent an email validation message. 
    Please copy and paste the one-time token in the email into the form below to validate your address. 
    If you did not receive an email, 
    <a href="validation.php?resend=<?php echo $safe_fuser; ?>">click here to resend it</a>.</p>
<?
}

if(isset($_REQUEST['token']) && EmailValidation::ValidateEmail($_REQUEST['token']))
{
    echo "<p><b>Your email has been validated.</b></p>";
}
else
{
    if(isset($_REQUEST['token']))
    {
        echo "<p><b>Invalid validation token.</b></p>";
    }
    ?>
        <p><b>Please enter your validation token:</b></p>

        <form action="validation.php" method="post">
            <input type="text" name="token" value="" />
            <input type="submit" name="validate" value="Validate Email" />
        </form>

    <?
}
?>

<?php
    include('ui/page_end.php');
?>
