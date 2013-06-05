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
require_once('inc/security.conf.php');

/*
 * Session data storage.
 * Works like a hash table. Very simple.
 *
 * To begin the session, call BeginSession to get a random session key.
 * To add a store a named value call SetValue using the session key.
 * To recall a named value call GetValue using the session key and the same key given to SetValue.
 * To end the session, call EndSession
 *
 * Keys must be short strings. Data values can be any type of serializable PHP variable.
 * i.e. anything PHP's 'serialize' method will accept.
 * 
 * NOTE: It is higly recommended that the session key is changed frequently. This
 *       class makes doing so very easy and quick. Just call NewSessionkey. I
 *       recommend changing the session key on every page load to frustrate
 *       session-stealing attacks.
 *
 * Important Features:
 *      - All data is encrypted so that the data in the database cannot be decrypted 
 *        without the session key.
 *      - Very easy to alternate change the session key very frequently.
 *
 */

// Default number of seconds until a new session expires.
// Property can be changed for a given session using the SetStaleTime method.
define('SESSION_DEFAULT_STALE_TIME', 2 * 24 * 3600);

class Session
{
    private function __construct() {}

    /*
     * Begin a new session.
     * $tag - An optional short string used to enforce exclusivity. If $tag is 
     *        set for one session and then another session is created with the 
     *        same $tag, the first session will be deleted. This is useful, for
     *        example, if you want the act of a user logging in to destroy 
     *        their other sessions.
     *
     * Returns: A new session is created and the session key is returned.
     *          The session key is a *binary* string.
     *          The session is set to expire in SESSION_DEFAULT_STALE_TIME seconds.
     *          FALSE is returned on error.
     */
    public static function BeginSession($tag = "")
    {
        global $SESSDB;

        $sesskey = Crypto::SecureRandom(SESSKEY_OCTETS);
        $sesskeyhash = self::SessionHash($sesskey);
        $datakey = Crypto::SecureRandom(SESSDATAKEY_OCTETS);
        $datakey = Crypto::Encrypt($datakey, $sesskey);
        $staletime = time() + SESSION_DEFAULT_STALE_TIME;
        
        if(!empty($tag))
        {
            self::DeleteTag($tag);
            $q = $SESSDB->prepare("INSERT INTO `smap` (sesskeyhash, datakey, tag, deleteafter) VALUES(:sesskeyhash, :datakey, :tag, :deleteafter)");
            $q->bindParam(':tag', $tag);
        }
        else
        {
            $q = $SESSDB->prepare("INSERT INTO `smap` (sesskeyhash, datakey, deleteafter) VALUES(:sesskeyhash, :datakey, :deleteafter)");
        }
        $q->bindParam(':sesskeyhash', $sesskeyhash);
        $q->bindParam(':datakey', $datakey);
        $q->bindParam(':deleteafter', $staletime);
        if($q->execute() === FALSE)
            return FALSE;
        else
        {
            return $sesskey;
        }
    }

    /*
     * Sets the expiration time for a session.
     * $sesskey - The session key.
     * $seconds - The number of seconds into the future when the session should expire.
     * Returns: FALSE on failure, TRUE on success.
     */
    public static function SetStaleTime($sesskey, $seconds)
    {
        global $SESSDB;

        if(!self::IsValidSession($sesskey))
            return FALSE;

        $sesskeyhash = self::SessionHash($sesskey);
        $expire = time() + $seconds;

        $q = $SESSDB->prepare("UPDATE `smap` SET deleteafter=:expire WHERE sesskeyhash=:sesskeyhash");
        $q->bindParam(':expire', $expire, PDO::PARAM_INT);
        $q->bindParam(':sesskeyhash', $sesskeyhash);
        $q->execute();

        return TRUE;
    }

    /*
     * Gets the number of seconds before a session expires.
     * $sesskey - The session key.
     * Returns: The number of seconds until the session expires.
     *          FALSE if the session has already expired or does not exist.
     */
    public static function GetTimeRemaining($sesskey)
    {
        //NOTE: This function is called by IsValidSession so it may not use it to validate the session.
        global $SESSDB;
        
        $q = $SESSDB->prepare("SELECT deleteafter FROM `smap` WHERE sesskeyhash=:sesskeyhash");
        $sesskeyhash = self::SessionHash($sesskey);
        $q->bindParam(':sesskeyhash', $sesskeyhash);
        $q->execute();
        $res = $q->fetch();

        if($res === FALSE)
            return FALSE;

        $remaining = (int)$res['deleteafter'] - time();
        if($remaining <= 0)
        {
            self::EndSession($sesskey);
            return FALSE;
        }
        else
        {
            return $remaining;
        }
    }

    /*
     * Removes all expired sessions.
     */
    public static function RemoveStaleSessions()
    {
        global $SESSDB;

        $time = time();

        // First delete everything in sdat that is data for an expired session
        $q = $SESSDB->prepare("DELETE FROM `sdat` WHERE sdat.id IN(SELECT smap.id FROM `smap` WHERE deleteafter < :time)");
        $q->bindParam(':time', $time);
        $q->execute();

        // Now delete the entries in smap
        $q = $SESSDB->prepare("DELETE FROM `smap` WHERE deleteafter < :time");
        $q->bindParam(':time', $time);
        $q->execute();
    }

    /*
     * Changes the session key for a session.
     * $sesskey - The current session key.
     * Returns: A new session key representing the same session.
     *          The old session key will no longer work.
     *          FALSE if the session has expired or does not exist.
     */
    public static function NewSessionKey($sesskey)
    {
        global $SESSDB;

        if(!self::IsValidSession($sesskey))
            return FALSE;

        $old_sesskeyhash = self::SessionHash($sesskey);

        $new_sesskey = Crypto::SecureRandom(SESSKEY_OCTETS);
        $new_sesskeyhash = self::SessionHash($new_sesskey);

        $datakey = self::GetDataKey($sesskey);
        $datakey = Crypto::Encrypt($datakey, $new_sesskey);

        $q = $SESSDB->prepare("UPDATE `smap` set sesskeyhash=:newsk, datakey=:newdatakey WHERE sesskeyhash=:old");
        $q->bindParam(':newsk', $new_sesskeyhash);
        $q->bindParam(':newdatakey', $datakey);
        $q->bindParam(':old', $old_sesskeyhash);
        $q->execute();
         
        return $new_sesskey;
    }

    /*
     * Checks if a session is valid.
     * $sesskey - The session key.
     * Returns: TRUE if the session is valid and has not expired, FALSE otherwise.
     */
    public static function IsValidSession($sesskey)
    {
        global $SESSDB;

        $sesskeyhash = self::SessionHash($sesskey);
        $q = $SESSDB->prepare("SELECT COUNT(sesskeyhash) FROM `smap` WHERE sesskeyhash=:sesskeyhash");
        $q->bindParam(':sesskeyhash', $sesskeyhash);
        if($q->execute() === FALSE)
            return FALSE;

        $count = $q->fetch();
        if($count[0] > 0)
        {
            if(self::GetTimeRemaining($sesskey) === FALSE)
            {
                self::EndSession($sesskey);
                return FALSE; // The session expired.
            }
            else
            {
                return TRUE; // Data exists and the timeout has not expired
            }
        }
        else
        {
            return FALSE; // No match.
        }
    }

    /*
     * Creates a key-value pair or changes the value for an existing key-value pair.
     * $sesskey - The session.
     * $key - The key used to identify this value.
     * $value - The value.
     * $value can be any serializable data type. See PHP's serialize function.
     * Returns: FALSE if the session does not exist or has expired.
     */
    public static function SetValue($sesskey, $key, $value)
    {
        global $SESSDB;
        if(($datakey = self::GetDataKey($sesskey)) !== FALSE)
        {
            $encrypted_value = Crypto::Encrypt(serialize($value), $datakey);
            $id = self::GetID($sesskey);

            if(self::KeyExists($id, $key))
                $q = $SESSDB->prepare("UPDATE `sdat` SET pvalue=:value WHERE id=:id AND pkey=:key");
            else
                $q = $SESSDB->prepare("INSERT INTO `sdat` (id, pkey, pvalue) VALUES(:id, :key, :value)");
            
            $q->bindParam(':id', $id);
            $q->bindParam(':key', $key);
            $q->bindParam(':value', $encrypted_value);
            if($q->execute() === FALSE)
                return FALSE;
            else
                return TRUE;
        }
        return FALSE;
    }

    /*
     * Removes a key-value pair from a session.
     * $sesskey - The session key.
     * $key - The key of the key-value pair.
     * Returns: TRUE if $key did not exist or was deleted. FALSE if the session does not exist or has expired.
     */
    public static function DeleteValue($sesskey, $key)
    {
        global $SESSDB;

        if(($id = self::GetID($sesskey)) !== FALSE)
        {
            $q = $SESSDB->prepare("DELETE FROM `sdat` WHERE id=:id AND pkey=:key");
            $q->bindParam(':id', $id);
            $q->bindParam(':key', $key);
            return $q->execute();
            return TRUE;
        }
        return FALSE;
    }

    /*
     * Gets the vaue of a key-value pair.
     * $sesskey - The session key.
     * $key - The key-value pair key.
     * Returns: The value, or FALSE if the key does not exist, or the session does not exist or has expired.
     */
    public static function GetValue($sesskey, $key)
    {
        global $SESSDB;
        if(($datakey = self::GetDataKey($sesskey)) !== FALSE)
        {
            $id = self::GetID($sesskey);
            if(!self::KeyExists($id, $key))
                return FALSE;
            $q = $SESSDB->prepare("SELECT pvalue FROM `sdat` WHERE id=:id AND pkey=:key");
            $q->bindParam(':id', $id);
            $q->bindParam(':key', $key);
            $q->execute();

            $data = $q->fetch();
            return unserialize(Crypto::Decrypt($data['pvalue'], $datakey));
        }
        return FALSE;
    }

    /* 
     * Invalidates and deletes all data associated with a session.
     * $sesskey - The session key.
     */
    public static function EndSession($sesskey)
    {
        //NOTE: This function is called by IsValidSession so it must NOT call it directly or indirectly.

        global $SESSDB;
        $sesskeyhash = self::SessionHash($sesskey);

        $q = $SESSDB->prepare("DELETE FROM `sdat` WHERE sdat.id IN(SELECT smap.id FROM `smap` WHERE sesskeyhash=:sesskeyhash)");
        $q->bindParam(':sesskeyhash', $sesskeyhash);
        $q->execute();

        $q = $SESSDB->prepare("DELETE FROM `smap` WHERE sesskeyhash=:sesskeyhash");
        $q->bindParam(':sesskeyhash', $sesskeyhash);
        $q->execute();
    }

    /*
     * Returns TRUE if a key exists for a session, FALSE if not.
     */
    private static function KeyExists($id, $key)
    {
        global $SESSDB;
        
        $q = $SESSDB->prepare("SELECT COUNT(id) FROM `sdat` WHERE id=:id AND pkey=:key");
        $q->bindParam(':id', $id, PDO::PARAM_INT);
        $q->bindParam(':key', $key);
        $q->execute();

        $result = $q->fetch();
        return $result[0] > 0;
    }

    /*
     * Returns the data encryption key for a session.
     */
    private static function GetDataKey($sesskey)
    {
        global $SESSDB;

        if(!self::IsValidSession($sesskey))
            return FALSE;

        $sesskeyhash = self::SessionHash($sesskey);

        $q = $SESSDB->prepare("SELECT datakey FROM `smap` WHERE sesskeyhash=:sesskeyhash");
        $q->bindParam(':sesskeyhash', $sesskeyhash);
        $q->execute();
        
        if(($datakey = $q->fetch()) !== FALSE)
        {
            $datakey = $datakey['datakey'];
            return Crypto::Decrypt($datakey, $sesskey);
        }
        return FALSE;
    }

    /*
     * Computes an irreverisble hash function on the session key.
     */
    private static function SessionHash($sesskey)
    {
        return Crypto::HashData($sesskey, SESSKEY_HASH_SALT);
    }

    /*
     * Removes all sessions maked with $tag.
     */
    private static function DeleteTag($tag)
    {
        global $SESSDB;
    
        // First delete entries in sdat
        $q = $SESSDB->prepare("DELETE FROM `sdat` WHERE sdat.id IN(SELECT smap.id FROM `smap` WHERE tag=:tag)");
        $q->bindParam(':tag', $tag);
        $q->execute();

        // Now smap...
        $q = $SESSDB->prepare("DELETE FROM `smap` WHERE tag=:tag");
        $q->bindParam(':tag', $tag);
        $q->execute();
    }

    /*
     * Returns the numerical ID of a session. This ID is used to find values in the sdat table.
     */
    private static function GetID($sesskey)
    {
        global $SESSDB;

        if(!self::IsValidSession($sesskey))
            return FALSE;

        $q = $SESSDB->prepare("SELECT id FROM `smap` WHERE sesskeyhash=:sesskeyhash");
        $sesskeyhash = self::SessionHash($sesskey);
        $q->bindParam(':sesskeyhash', $sesskeyhash);
        $q->execute();

        $res = $q->fetch();
        return (int)$res['id'];
    }
}
?>
