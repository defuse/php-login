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
require_once('security/Crypto.php');
require_once('inc/session.php');
require_once('inc/security.conf.php');
require_once('inc/log.php');
require_once('inc/email.php');
require_once('inc/mutex.php');
require_once('security/Filter.php');
require_once('inc/EmailValidation.php');
require_once('inc/UserLockout.php');

//TODO: Handle different case usernames... need to add $username = strtolower?
//TODO: Look at secure connnections to MySQL
//TODO: soem kind of events script for changepasswords
//TODO: optional syslog
//TODO: class naming as per http://www.php.net/manual/en/userlandnaming.tips.php
//TODO: Make sure this supports cross-browser-close sessions (optional, by security constant), etc
//TODO: Username characters and length policy (don't put in CreateAccount, make method for it)
//TODO: Handle decryption failures better (ciphertext tampering)
//TODO: static "mini-lockout" before actual lockout (1minute or so?)
//TODO: Unlock EMAILs should NOTTTT contain a link but should contain a copy paste thing
//TODO: List active users
//TODO: check if register globals is on and completely refuse to run
//TODO: Load db creds from configurable out-of-web-root flat text file
//TODO: Lock session to IP ***NOTTTTT USER AGENT*** because some proxies change it randomly
//TODO: put configuration (and even all of the include files) outside of www-root
//TODO: Support for user TYPES (access control)

class Accounts
{
    private function __construct() {}

    /*
     * Creates a user account.
     * $username - The username of the new account.
     * $password - The password of the new account.
     * Returns: boolean TRUE if the account was successsfully created.
     *          boolean FALSE if there was some error, i.e:
     *              - username already exists
     */
    public static function CreateAccount($username, $email, $password, $allowreset)
    {
        global $USERDB;

        $propercase = $username;
        $username = strtolower($username);

        if(!Filter::IsValidUsername($propercase))
            return FALSE;
        
        if(!Filter::IsValidEmail($email))
            return FALSE;

        if(self::UserExists($username)) // User with this name already exists
        {
            return FALSE;
        }
        else
        {
            // Hash the password
            $hash = Crypto::HashPassword($password);

            // Create a random master key for data encryption
            $masterkey = Crypto::SecureRandom(SERVERSIDE_KEY_SIZE);

            // Create a random user-unique salt
            $salt = bin2hex(Crypto::SecureRandom(SERVERSIDE_SALT_OCTETS));

            // Derrive the key encryption key (KEK) from the password and user salt
            $passwordkey = Crypto::CreateKey($password, "key/password", SERVERSIDE_KEY_SIZE, $salt);

            // Encrypt the master key with the KEK
            $masterkey = Crypto::Encrypt($masterkey, $passwordkey);

            $validated = 0;

            if(!REQUIRE_EMAIL_VALIDATION)
                $validated = 1;

            $reset = 0;
            if($allowreset)
                $reset = 1;

            //TODO: Make the default lock values a setting
            $q = $USERDB->prepare("INSERT INTO `userauth` (
                                        username, propercase, auth, salt, 
                                        masterkey, email, validated, allowreset,
                                        enablelock, allowlockbypass
                                    ) VALUES (
                                        :username, :propercase, :auth,
                                        :salt, :masterkey, :email, :validated, :allowreset,
                                        '1', '1'
                                    )");
            $q->bindParam(':username', $username, PDO::PARAM_STR);
            $q->bindParam(':propercase', $propercase, PDO::PARAM_STR);
            $q->bindParam(':auth', $hash, PDO::PARAM_STR);
            $q->bindParam(':salt', $salt, PDO::PARAM_STR); 
            $q->bindParam(':email', $email, PDO::PARAM_STR); 
            $q->bindParam(':validated', $validated, PDO::PARAM_INT); 
            $q->bindParam(':allowreset', $reset, PDO::PARAM_INT); 
            $q->bindParam(':masterkey', $masterkey);

            if($q->execute() === FALSE)
            {
                Log::LogError("Error adding user to database.", LOG_LEVEL_CRITICAL);
                return FALSE;
            }

            if(REQUIRE_EMAIL_VALIDATION)
            {
                EmailValidation::SendValidationEmail($propercase, $email);
            }
            return TRUE; //TODO: handle error conditions better
        }
    }

    public static function GetProperUsername($username)
    {
        global $USERDB;
        $username = strtolower($username);

        $q = $USERDB->prepare("SELECT propercase FROM `userauth` WHERE username=:username");
        $q->bindParam(':username', $username);
        $q->execute();

        if(($res = $q->fetch()) !== FALSE)
        {
            return $res['propercase'];
        }
        else
            return FALSE;
    }

    public static function DeleteAccount($username)
    {
        global $USERDB;

        $userid = self::GetUserID($username);
        if($userid !== FALSE)
        {
             $q = $USERDB->prepare("DELETE FROM `userauth` WHERE id=:id");
             $q->bindParam(':id', $userid, PDO::PARAM_INT);
             $q->execute();

             $q = $USERDB->prepare("DELETE FROM `user_data` WHERE user=:id");
             $q->bindParam(':id', $userid, PDO::PARAM_INT);
             $q->execute();

             $q = $USERDB->prepare("DELETE FROM `user_encrypted_data` WHERE user=:id");
             $q->bindParam(':id', $userid, PDO::PARAM_INT);
             $q->execute();
        }
    }

    /*
     * Checks if a user's password is correct.
     * $username - The account username.
     * $password - The password to check.
     * Returns: TRUE if correct, FALSE otherwise.
     */
    public static function CheckPassword($username, $password)
    {
        global $USERDB;
        $username = strtolower($username);

        if(UserLockout::IsLockedOut($username))
            return FALSE;

        $search = $USERDB->prepare("SELECT auth FROM `userauth` WHERE username=:username");
        $search->bindParam(':username', $username);
        $search->execute();

        if(($user = $search->fetch()) !== FALSE)
        {
            return Crypto::ValidatePassword($password, $user['auth']);
        }
        return FALSE;
    }

    public static function LockCheckPassword($username, $password)
    {
        // This may seem redundant but it's not.
        // When the user attempts to login after they have been locked out,
        // it shouldn't count as another authentication failure.
        // This is OK since the attacker will not be able to determine
        // whether the password used was right or wrong.
        if(UserLockout::IsLockedOut($username))
            return FALSE;

        if(self::CheckPassword($username, $password))
        {
            return TRUE;
        }
        else
        {
            UserLockout::AddAuthFailure($username);
            return FALSE;
        }
    }

    public static function ChangePassword($username, $password, $newpassword)
    {
        global $USERDB;
        $username = strtolower($username);

        // The password will be hashed if clientside hashing is enabled, so we can't check it
        if(ENABLE_CLIENTSIDE_HASH == FALSE && !Filter::ConformsToPasswordPolicy($newpassword))
        {
            return FALSE;
        }

        if(!self::LockCheckPassword($username, $password))
            return FALSE;

        if(($masterkey = self::GetUserMasterKey($username, $password)) !== FALSE)
        {
            $salt = self::GetUserSalt($username);
            $hash = Crypto::HashPassword($newpassword);
            // Get the new password key derrived from the new password
            $passwordkey = Crypto::CreateKey($newpassword, "key/password", SERVERSIDE_KEY_SIZE, $salt);
            // Encrypt the master key with the new password key
            $new_master_key = Crypto::Encrypt($masterkey, $passwordkey);

            $q = $USERDB->prepare("UPDATE `userauth` SET auth=:hash, masterkey=:masterkey WHERE username=:username");
            $q->bindParam(':hash', $hash);
            $q->bindParam(':masterkey', $new_master_key);
            $q->bindParam(':username', $username);
            $q->execute();

            return TRUE;
        }
        return FALSE;
    }

    // NOTE: ALL encrypted data will be lost
    public static function AdministratorChangePassword($username, $newpassword, $hash = true)
    {
        global $USERDB;
        $username = strtolower($username);

        if(!Filter::ConformsToPasswordPolicy($newpassword))
        {
            return FALSE;
        }

        // Emulate JavaScript hashing if it's enabled
        if(ENABLE_CLIENTSIDE_HASH && $hash)
        {
            $newpassword = Crypto::EmulateClientSideHash($newpassword, $username);
        }

        // Hash the password
        $hash = Crypto::HashPassword($newpassword);

        // Create a random master key for data encryption
        $masterkey = Crypto::SecureRandom(SERVERSIDE_KEY_SIZE);

        // Get the user's salt
        // NOTE: We don't change the salt here as it may be used for other purposes.
        $salt = self::GetUserSalt($username);

        // Derrive the key encryption key (KEK) from the password and user salt
        $passwordkey = Crypto::CreateKey($newpassword, "key/password", SERVERSIDE_KEY_SIZE, $salt);

        // Encrypt the master key with the KEK
        $masterkey = Crypto::Encrypt($masterkey, $passwordkey);

        $q = $USERDB->prepare("UPDATE `userauth` SET auth=:hash, masterkey=:masterkey WHERE username=:username");
        $q->bindParam(':hash', $hash);
        $q->bindParam(':masterkey', $masterkey);
        $q->bindParam(':username', $username);
        $q->execute();

        // Remove all of the user's encrypted data since the key to decrypt it has been lost.
        $id = self::GetUserID($username);
        $q = $USERDB->prepare("DELETE FROM `user_encrypted_data` WHERE user=:id");
        $q->bindParam(':id', $id, PDO::PARAM_INT);
        $q->execute();

        return TRUE;
    }

    public static function UserExists($username)
    {
        return self::IsUsernameReserved($username) || self::GetUserID($username) !== FALSE;
    }

    public static function IsUsernameReserved($username)
    {
        global $RESERVED_USERS;
        $username = strtolower($username);
        return in_array($username, $RESERVED_USERS);
    }

    /*
     * Returns the user-specific random salt value set at account creation time.
     * $username - The account username.
     */
    public static function GetUserSalt($username)
    {
        global $USERDB;
        $username = strtolower($username);

        $salt = $USERDB->prepare("SELECT salt FROM `userauth` WHERE username=:username");
        $salt->bindParam(':username', $username);
        if($salt->execute() !== FALSE)
        {
            $salt = $salt->fetch();
            if($salt === FALSE)
                return FALSE;
            $salt = $salt['salt'];
            return $salt;
        }
        return FALSE;
    }

    public static function GetUserID($username)
    {
        global $USERDB;
        $username = strtolower($username);

        $id = $USERDB->prepare("SELECT id FROM `userauth` WHERE username=:username");
        $id->bindParam(':username', $username);
        if($id->execute() !== FALSE)
        {
            $id = $id->fetch();
            if($id === FALSE)
                return FALSE;
            $id = $id['id'];
            return $id;
        }
        return FALSE;
    }

    public static function GetUserMasterKey($username, $password)
    {
        global $USERDB;
        $username = strtolower($username);

        if(self::CheckPassword($username, $password))
        {
            // Derrive the key encryption key (KEK) from the password and user salt
            $salt = self::GetUserSalt($username);
            $passwordkey = Crypto::CreateKey($password, "key/password", SERVERSIDE_KEY_SIZE, $salt);

            $q = $USERDB->prepare("SELECT masterkey FROM `userauth` WHERE username=:username");
            $q->bindParam(':username', $username);
            $q->execute();
            $masterkey = $q->fetch();
            $masterkey = $masterkey['masterkey'];
            $masterkey = Crypto::Decrypt($masterkey, $passwordkey);
            return $masterkey;
        }
        else
        {
            return FALSE;
        }
    }

    public static function GetUserEmail($username)
    {
        global $USERDB;
        $username = strtolower($username);

        $q = $USERDB->prepare("SELECT email FROM `userauth` WHERE username=:username");
        $q->bindParam(':username', $username);
        $q->execute();

        return $q->fetchColumn();
    }
}
?>
