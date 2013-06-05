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

//TODO: fuck the function coments, clean up params

require_once('inc/accounts.php');
require_once('inc/session.php');
require_once('inc/EmailValidation.php');
require_once('security/Crypto.php');
require_once('inc/dblogin.php');

class UserLogin
{
    private function __construct() {}

    /*
     * Login - Checks if a user exists and that the password is correct.
     * $username - The account username.
     * $password - The account password.
     * $time - The number of seconds to stay logged in.
     * Returns: If the username and password are correct, a new session key with
     *          state set to remember that the user is logged in. Or, if the
     *          username or password are incorrect, boolean FALSE.
     */
    public static function Login($username, $password, $time = MAX_SESSION_LIFE, $lockbypass = null)
    {
        global $LOCK_BYPASS;
        $LOCK_BYPASS = $lockbypass;

        $username = strtolower($username);
        $userid = Accounts::GetUserID($username);
        if(Accounts::LockCheckPassword($username, $password))
        {
            if(REQUIRE_EMAIL_VALIDATION && !EmailValidation::IsUserValidated($username))
                return FALSE;

            $masterkey = Accounts::GetUserMasterKey($username, $password);

            // Fail safe: If we can't get the master key for some reason, don't let them log in.
            // Because we REALLY don't want to be encrypting data with the key "FALSE"
            if($masterkey === FALSE)
            {
                return FALSE;
            }

            // Tag the session with username so subsequent logins as this user destroy this session.
            $sesskey = Session::BeginSession($username);
            Session::SetStaleTime($sesskey, $time);
            Session::SetValue($sesskey, '_username', $username);
            Session::SetValue($sesskey, '_masterkey', $masterkey);
            Session::SetValue($sesskey, '_userid', $userid);

            if(RECORD_LOGIN_HISTORY)
            {
                self::RecordLoginEvent($userid, TRUE, $masterkey);
            }

            return $sesskey;
        }
        if(RECORD_LOGINFAIL_HISTORY && $userid !== FALSE)
        {
            self::RecordLoginEvent($userid, FALSE);
        }
        return FALSE;
    }

    private static function RecordLoginEvent($userid, $success, $masterkey = null)
    {
        // The IP and User Agent MUST be truncated to fit - or else an attacker
        // can exclude himself from the log by using a huge user agent.
        // These are the lengths of the 'ipaddr' and 'agent' VARBINARY columns...
        $LOGINEVENT_MAX_USERAGENT = 4096;
        $LOGINEVENT_MAX_IP = 1024;

        global $USERDB;

        $table = $success ? 'login_history' : 'login_fail_history';
        $q = $USERDB->prepare("INSERT INTO `$table` (user, ipaddr, time, agent) 
                               VALUES (:user, :ip, :time, :agent)");
        
        $ip = isset($_SERVER['REMOTE_ADDR']) ? $_SERVER['REMOTE_ADDR'] : "not_given";
        $ip = substr($ip, 0, $LOGINEVENT_MAX_IP / 2); // Assume encryption doubles the length
        if($success && $masterkey != null && ENCRYPT_LOGIN_HISTORY_IP) 
            $ip = Crypto::Encrypt($ip, $masterkey);

        $agent = isset($_SERVER['HTTP_USER_AGENT']) ? $_SERVER['HTTP_USER_AGENT'] : "not_given";
        $agent = substr($agent, 0, $LOGINEVENT_MAX_USERAGENT / 2); // Assume encryption doubles the length
        if($success && $masterkey != null && ENCRYPT_LOGIN_HISTORY_AGENT)
            $agent = Crypto::Encrypt($agent, $masterkey);

        $q->bindParam(':user', $userid, PDO::PARAM_INT);
        $q->bindParam(':ip', $ip, PDO::PARAM_STR);
        $now = time();
        $q->bindParam(':time', $now, PDO::PARAM_INT);
        $q->bindParam(':agent', $agent, PDO::PARAM_STR);
        $q->execute();
    }

    /*
     * CookieLogin - Login and set cookie(s) to remember login state.
     * $username - The account username.
     * $password - The account password.
     * $time - The number of seconds to stay logged in.
     * $expireOnClose - TRUE to make the cookie expire when the browser is closed.
     * If $expireOnClose is FALSE, the cookie will be set to expire after $time
     * seconds. The session will always expire after $time seconds regardless of
     * whether $expireOnClose is true or false.
     * Returns: (See Login)
     */
    public static function CookieLogin($username, $password, $time = MAX_SESSION_LIFE, 
                                       $lockbypass = null, $expireOnClose = TRUE)
    {
        $sesskey = self::Login($username, $password, $time, $lockbypass);
        if($sesskey === FALSE)
            return FALSE;

        $expire = 0;
        if(!$expireOnClose)
            $expire = time() + $time;
        Session::SetValue($sesskey, '_cookie_expire', $expire);
        setcookie('session', bin2hex($sesskey), $expire,
                  COOKIE_PATH, 
                  COOKIE_DOMAIN, 
                  COOKIE_SECURE, 
                  COOKIE_HTTPONLY );
        return $sesskey;
    }

    public static function CookieRandomizeSession()
    {
        if(isset($_COOKIE['session']))
        {
            $sesskey = Crypto::hex2bin($_COOKIE['session']);
            if(!Session::IsValidSession($sesskey))
                return;
            $expire = Session::GetValue($sesskey, '_cookie_expire');
            if($expire === FALSE)
                return;
            $sesskey = Session::NewSessionKey($sesskey);
            setcookie('session', bin2hex($sesskey), $expire, 
                      COOKIE_PATH, 
                      COOKIE_DOMAIN, 
                      COOKIE_SECURE, 
                      COOKIE_HTTPONLY );
        }
    }

    public static function GetCurrentUser($sesskey)
    {
        if(Session::IsValidSession($sesskey))
        {
            $username = Session::GetValue($sesskey, '_username');
            $userid = Session::GetValue($sesskey, '_userid');
            $masterkey = Session::GetValue($sesskey, '_masterkey');

            if($username === FALSE || $userid === FALSE || $masterkey === FALSE)
                return FALSE;
            else
            {
                if(Accounts::GetUserID($username) === FALSE)
                {
                    Session::EndSession($sesskey);
                    return FALSE;
                }
                return new LoggedInUser($username, $userid, $masterkey);
            }
        }
        else
        {
            return FALSE;
        }
    }

    public static function CookieGetCurrentUser()
    {
        if(isset($_COOKIE['session']))
        {
            $sesskey = Crypto::hex2bin($_COOKIE['session']);
            return self::GetCurrentUser($sesskey);
        }
        else
        {
            return FALSE;
        }
    }

    public static function LogOut($sesskey)
    {
        Session::EndSession($sesskey);
    }

    public static function CookieLogOut()
    {
        if(isset($_COOKIE['session']))
        {
            $sesskey = Crypto::hex2bin($_COOKIE['session']);
            Session::EndSession($sesskey);
            setcookie('session', 'logout', 1, 
                      COOKIE_PATH,
                      COOKIE_DOMAIN,
                      COOKIE_SECURE,
                      COOKIE_HTTPONLY );
        }
    }

}
?>
