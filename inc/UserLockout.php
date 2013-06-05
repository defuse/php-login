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

//TODO: refactor this pos
require_once('inc/accounts.php');
require_once('inc/dblogin.php');
require_once('inc/email.php');
require_once('inc/log.php');
require_once('security/Crypto.php');
require_once('inc/security.conf.php');

class UserLockout 
{
    private function __construct() {}

    public static function IsLockEnabled($username)
    {
        global $USERDB;
        $username = strtolower($username);

        $q = $USERDB->prepare("SELECT enablelock FROM `userauth` WHERE username=:username");
        $q->bindParam(':username', $username);
        $q->execute();

        $res = $q->fetchColumn();
        if($res !== FALSE && $res == "1")
            return TRUE;
        else
            return FALSE;
    }

    public static function IsLockBypassEnabled($username)
    {
        global $USERDB;
        $username = strtolower($username);

        $q = $USERDB->prepare("SELECT allowlockbypass FROM `userauth` WHERE username=:username");
        $q->bindParam(':username', $username);
        $q->execute();

        $res = $q->fetchColumn();
        if($res !== FALSE && $res == "1")
            return TRUE;
        else
            return FALSE;
    }
    
    public static function SetLockEnabled($username, $enabled)
    {
        global $USERDB;
        $username = strtolower($username);
        $enabled = ($enabled) ? 1 : 0;

        $q = $USERDB->prepare("UPDATE `userauth` SET enablelock=:enabled WHERE username=:username");
        $q->bindParam(':enabled', $enabled);
        $q->bindParam(':username', $username);
        $q->execute();
    }

    public static function SetLockBypassEnabled($username, $enabled)
    {
        global $USERDB;
        $username = strtolower($username);
        $enabled = ($enabled) ? 1 : 0;

        $q = $USERDB->prepare("UPDATE `userauth` SET allowlockbypass=:enabled WHERE username=:username");
        $q->bindParam(':enabled', $enabled);
        $q->bindParam(':username', $username);
        $q->execute();
    }

    public static function AddAuthFailure($username)
    {
        global $USERDB;

        $userid = Accounts::GetUserID($username);
        $time = time();

        if($userid === FALSE)
            return;

        // Don't bother logging failures for users who have opted out of the lock feature
        if(!self::IsLockEnabled($username))
            return;

        //TODO: is this good enough to prevent the attack?
        $mutex = new Mutex("lockout_count");
        $mutex->lock(); // Fail safe: If lock fails, add the failure in the "unsafe" way.

        $q = $USERDB->prepare("INSERT INTO `lockout` (user, eventtime) VALUES(:user, :time)");
        $q->bindParam(':user', $userid);
        $q->bindParam(':time', $time);
        $q->execute();

        $mutex->unlock();
    }

    public static function IsLockedOut($username, $lockbypass = null)
    {
        global $USERDB;
        global $LOCK_BYPASS;
        $time = time();

        // Don't say a user that doesn't exist is locked out
        if(Accounts::UserExists($username) === FALSE)
            return FALSE;

        // Users who have opted out of the lock feature are never locked out.
        if(!self::IsLockEnabled($username))
        {
            return FALSE;
        }

        // Allow the lock to be bypassed given the appropriate token...
        if(isset($LOCK_BYPASS) && !is_null($LOCK_BYPASS) && 
            self::TestUnlockBypassToken($username, $LOCK_BYPASS))
        {
            return FALSE;
        }

        $userid = Accounts::GetUserID($username);

        // Delete irrelevant entries to keep the table small
        $old = $time - LOCKOUT_TIMESPAN;
        $q = $USERDB->prepare("DELETE FROM `lockout` WHERE eventtime < :old");
        $q->bindParam(':old', $old);
        $q->execute();

        // See if the user is already locked out
        $q = $USERDB->prepare("SELECT lockout FROM `userauth` WHERE id=:userid");
        $q->bindParam(':userid', $userid);
        $q->execute();
        $res = $q->fetch();
        if($res['lockout'] > $time)
            return TRUE;
        // User was locked out but the lockout period expired
        elseif($res['lockout'] > 0 && $res['lockout'] < $time)
        {
            // Reset the lockout expire time to 0
            // This isn't strictly necessary, but it keeps things consistent
            $q = $USERDB->prepare("UPDATE `userauth` SET lockout='0' WHERE id=:userid"); 
            $q->bindParam(':userid', $userid);
            $q->execute();
            // Note that we can't return here because the user may still be locked out
            // due to actions recorded in the `lockout` table.
        }
        
        $mutex = new Mutex("lockout_count");
        if($mutex->lock())
        {
            // Find out how many failed login attempts have been made for the user 
            // in the past LOCKOUT_TIMESPAN seconds.
            $q = $USERDB->prepare("SELECT COUNT(eventtime) FROM `lockout` WHERE user=:userid AND eventtime >= :old");
            $q->bindParam(':userid', $userid);
            $q->bindParam(':old', $old);
            $q->execute();
            $num_failures = (int)$q->fetchColumn();

            // If the lockout policy is violated.. 
            // (LOCKOUT_MAX_FAILURES in LOCKOUT_TIMESPAN seconds)
            if($num_failures >= LOCKOUT_MAX_FAILURES)
            {
                $lockout_end = time() + LOCKOUT_DURATION;
                $q = $USERDB->prepare("UPDATE `userauth` SET lockout=:lockend WHERE id=:userid");
                $q->bindParam(':lockend', $lockout_end);
                $q->bindParam(':userid', $userid);
                $q->execute();
                Log::LogError("Account [$username] was locked out", LOG_LEVEL_NOTICE);
                if(SEND_LOCKOUT_ALERT)
                    self::SendLockoutAlert($username);
                $mutex->unlock();
                return TRUE;
            }
            $mutex->unlock();
            return FALSE;
        }
        else
        {
            return TRUE; // Fail safe
        }
    }

    public static function RemoveStaleTokens()
    {
        global $USERDB;

        $now = time();
        $expire = $now - UNLOCK_TOKEN_LIFETIME;
        $q = $USERDB->prepare("DELETE FROM `lockout_tokens` WHERE createtime < :expire");
        $q->bindParam(':expire', $expire);
        $q->execute();
    }

    private static function SendLockoutAlert($username)
    {
        $email = Accounts::GetUserEmail($username);
        $macros = array(
            "%%USERNAME%%" => Accounts::GetProperUsername($username)
        );
        Email::SendMacroMail(LOCKOUT_ALERT_SOURCE_ADDR, $email, LOCKOUT_ALERT_SUBJECT, "lockoutalert", $macros);
    }

    public static function SendUnlockToken($username)
    {
        global $USERDB;

        if(!self::IsLockedOut($username) || !self::IsLockBypassEnabled($username))
            return FALSE;

        $userid = Accounts::GetUserID($username);
        if($userid === FALSE)
            return FALSE;
        $email = Accounts::GetUserEmail($username);
        $token = bin2hex(Crypto::SecureRandom(UNLOCK_TOKEN_OCTETS));

        $macros = array(
            "%%USERNAME%%" => Accounts::GetProperUsername($username),
            "%%TOKEN%%" => $token
        );

        $q = $USERDB->prepare("INSERT INTO `lockout_tokens` (token, userid, createtime) 
                                VALUES(:token, :userid, :createtime)");
        $q->bindParam(':token', $token, PDO::PARAM_STR);
        $q->bindParam(':userid', $userid, PDO::PARAM_INT);
        $q->bindParam(':createtime', time(), PDO::PARAM_INT);
        $q->execute();

        Email::SendMacroMail(UNLOCK_TOKEN_SOURCE_ADDR, $email, UNLOCK_TOKEN_SUBJECT, "unlocktoken", $macros);
        return TRUE;
    }

    public static function TestUnlockBypassToken($username, $token)
    {
        global $USERDB;
        $userid = Accounts::GetUserID($username);

        if(!self::IsLockBypassEnabled($username))
        {
            return FALSE;
        }
        
        $q = $USERDB->prepare("SELECT userid, createtime FROM `lockout_tokens` WHERE token=:token");
        $q->bindParam(':token', $token, PDO::PARAM_STR);
        $q->execute();

        $res = $q->fetch();

        $real_id = (int)$res['userid'];
        $expire = (int)$res['createtime'] + UNLOCK_TOKEN_LIFETIME;
        $now = time();
        if($userid == $real_id && $now < $expire)
        {
            return TRUE;
        }

        if($now >= $expire)
        {
            $q = $USERDB->prepare("DELETE FROM `lockout_tokens` WHERE token=:token");
            $q->bindParam(':token', $token, PDO::PARAM_STR);
            $q->execute();
        }

        return FALSE;
    }
}
?>
