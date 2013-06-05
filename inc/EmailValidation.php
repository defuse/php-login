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
require_once('inc/dblogin.php');
require_once('inc/accounts.php');
require_once('security/Crypto.php');
require_once('inc/email.php');

class EmailValidation
{
    private function __construct() {}

    public static function SendValidationEmail($username, $email)
    {
        $userid = Accounts::GetUserID($username);
        $token = self::CreateValidationToken($userid);
        $macros = array(
            "%%USERNAME%%" => $username,
            "%%TOKEN%%" => $token
        );
        Email::SendMacroMail(EMAIL_VALIDATION_SOURCE_ADDR, $email, EMAIL_VALIDATION_SUBJECT, 
                            "emailvalidation", $macros);
    }

    public static function SetUserValidatedByID($userid)
    {
        global $USERDB;
        $q = $USERDB->prepare("UPDATE `userauth` SET validated='1' WHERE id=:id");
        $q->bindParam(':id', $userid, PDO::PARAM_INT);
        $q->execute();
    }

    public static function SetUserValidatedByName($username)
    {
        global $USERDB;
        $q = $USERDB->prepare("UPDATE `userauth` SET validated='1' WHERE username=:username");
        $q->bindParam(':username', $username, PDO::PARAM_STR);
        $q->execute();
    }

    public static function ValidateEmail($token)
    {
        if(self::IsValidToken($token))
        {
            $userid = self::GetTokenUserID($token);
            self::SetUserValidatedByID($userid);
            self::RemoveEmailToken($token);
            return TRUE;
        }
        else
            return FALSE;
    }

    public static function IsUserValidated($username)
    {
        global $USERDB;
        $username = strtolower($username);

        $q = $USERDB->prepare("SELECT validated FROM `userauth` WHERE username=:username");
        $q->bindParam(':username', $username);
        $q->execute();

        $validated = (int)$q->fetchColumn();
        return $validated == 1;
    }

    public static function RemoveStaleTokens()
    {
        global $USERDB;
        $now = time();
        $expire = $now - EMAIL_VALIDATION_TOKEN_LIFETIME;
        $q = $USERDB->prepare("DELETE FROM `validation_tokens` WHERE createtime < :expire");
        $q->bindParam(':expire', $expire);
        $q->execute();
    }


    private static function CreateValidationToken($userid)
    {
        global $USERDB;

        $token = bin2hex(Crypto::SecureRandom(EMAIL_VALIDATION_TOKEN_OCTETS));

        $q = $USERDB->prepare("INSERT INTO `validation_tokens` (token, userid, createtime)
                               VALUES (:token, :userid, :createtime)");
        $q->bindParam(':token', $token, PDO::PARAM_STR);
        $q->bindParam(':userid', $userid, PDO::PARAM_INT);
        $now = time();
        $q->bindParam(':createtime', $now, PDO::PARAM_INT);
        $q->execute();

        return $token;
    }

    private static function RemoveEmailToken($token)
    {
        global $USERDB;
        $q = $USERDB->prepare("DELETE FROM `validation_tokens` WHERE token=:token");
        $q->bindParam(':token', $token, PDO::PARAM_STR);
        $q->execute();
    }

    private static function GetTokenUserID($token)
    {
        $tokenInfo = self::GetTokenInfo($token);
        if($tokenInfo === FALSE)
            return FALSE;
        else
            return (int)$tokenInfo['userid'];
    }

    private static function IsValidToken($token)
    {
        $tokenInfo = self::GetTokenInfo($token);
        if($tokenInfo === FALSE)
            return FALSE;

        if(time() < $tokenInfo['createtime'] + EMAIL_VALIDATION_TOKEN_LIFETIME)
            return TRUE;
        else 
        {
            self::RemoveEmailToken($token);
            return FALSE;
        }
    }

    private static function GetTokenInfo($token)
    {
        global $USERDB;
        $q = $USERDB->prepare("SELECT * FROM `validation_tokens` WHERE token=:token");
        $q->bindParam(':token', $token, PDO::PARAM_STR);
        $q->execute();
        return $q->fetch();
    }
}

?>
