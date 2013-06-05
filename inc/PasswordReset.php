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

require_once('inc/dblogin.php');
require_once('inc/accounts.php');
require_once('inc/email.php');
require_once('inc/EmailValidation.php');
require_once('security/Crypto.php');
require_once('inc/security.conf.php');

class PasswordReset 
{
    private function __construct() {}

    public static function SetResetEnabled($username, $enabled)
    {
        global $USERDB;
        $username = strtolower($username);
        $enabled = ($enabled) ? 1 : 0;

        $q = $USERDB->prepare("UPDATE `userauth` SET allowreset=:enabled WHERE username=:username");
        $q->bindParam(':enabled', $enabled);
        $q->bindParam(':username', $username);
        $q->execute();
    }

    public static function SendPasswordResetEmail($username)
    {
        //TODO: HAndle email-not-on-file
        //TODO: Check if allow reset
        //TODO: Send a warning message (no reset token) if they don't have reset enabled
        global $USERDB;

        $userid = Accounts::GetUserID($username);
        if($userid === FALSE || !EmailValidation::IsUserValidated($username))
            return FALSE;

        $email = Accounts::GetUserEmail($username);

        if(!self::IsPasswordResetAllowed($username))
        {
            $macros = array(
                "%%USERNAME%%" => Accounts::GetProperUsername($username)
            );
            Email::SendMacroMail(RESET_TOKEN_SOURCE_ADDR, $email, RESET_DISABLED_SUBJECT, "resetdisabled", $macros);
            return FALSE;
        }

        $token = bin2hex(Crypto::SecureRandom(RESET_TOKEN_OCTETS));

        $macros = array(
            "%%USERNAME%%" => Accounts::GetProperUsername($username),
            "%%TOKEN%%" => $token
        );

        $q = $USERDB->prepare("INSERT INTO `reset_tokens` (token, userid, createtime) 
                                VALUES(:token, :userid, :createtime)");
        $q->bindParam(':token', $token, PDO::PARAM_STR);
        $q->bindParam(':userid', $userid, PDO::PARAM_INT);
        $q->bindParam(':createtime', time(), PDO::PARAM_INT);
        $q->execute();

        Email::SendMacroMail(RESET_TOKEN_SOURCE_ADDR, $email, RESET_TOKEN_SUBJECT, "resetaccount", $macros);
        return TRUE;
    }

    //TODO: Test case: make SURE the token is useless after used
    //TODO: Race condition
    public static function UserPasswordReset($token, $username, $newpassword)
    {
        global $USERDB;
        $userid = Accounts::GetUserID($username);

        if($userid === FALSE || !self::IsPasswordResetAllowed($username))
            return FALSE;

        $q = $USERDB->prepare("SELECT userid, createtime FROM `reset_tokens` WHERE token=:token");
        $q->bindParam(':token', $token, PDO::PARAM_STR);
        $q->execute();

        $res = $q->fetch();
        $real_id = (int)$res['userid'];
        $expire = (int)$res['createtime'] + RESET_TOKEN_LIFETIME;
        $now = time();
        if($userid != $real_id || $now >= $expire)
        {
            return FALSE;
        }

        // Never let a reset token be reused
        $q = $USERDB->prepare("DELETE FROM `reset_tokens` WHERE token=:token");
        $q->bindParam(':token', $token, PDO::PARAM_STR);
        $q->execute();

        return Accounts::AdministratorChangePassword($username, $newpassword, FALSE);
    }

    public static function IsPasswordResetAllowed($username)
    {
        global $USERDB;
        $username = strtolower($username);

        if(!Accounts::UserExists($username))
            return FALSE;

        $q = $USERDB->prepare("SELECT allowreset FROM `userauth` WHERE username=:username");
        $q->bindParam(':username', $username);
        $q->execute();

        $res = $q->fetchColumn();
        return $res == 1;
    }

    public static function RemoveStaleTokens()
    {
        global $USERDB;
        $now = time();
        $expire = $now - RESET_TOKEN_LIFETIME;
        $q = $USERDB->prepare("DELETE FROM `reset_tokens` WHERE createtime < :expire");
        $q->bindParam(':expire', $expire);
        $q->execute();
    }

}

?>
