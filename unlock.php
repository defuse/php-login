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
require_once('inc/UserLockout.php');

if(isset($_REQUEST['token']) && isset($_REQUEST['username']) &&
    UserLockout::TestUnlockBypassToken($_REQUEST['username'], $_REQUEST['token']))
{
    setcookie("_lockbypass", $_REQUEST['token'], 0, COOKIE_PATH, COOKIE_DOMAIN, COOKIE_SECURE, COOKIE_HTTPONLY);
    include('ui/page_top.php');
    echo "<p><b>Your browser has been given a cookie that allows it to login even though your account is locked. You may now attempt to login.</b></p>";
}
else
{
    include('ui/page_top.php');
    if(isset($_REQUEST['token']))
    {
        echo "<p><b>Invalid unlock token.</b></p>";
    }
    ?>
        <p><b>Please enter your unlock bypass token and username:</b></p>

        <form action="unlock.php" method="post">
            Token: <input type="text" name="token" value="" />
            Username: <input type="text" name="username" value="" />
            <input type="submit" name="bypass" value="Bypass Lock" />
        </form>
    <?
}
?>

<?php
    include('ui/page_end.php');
?>
