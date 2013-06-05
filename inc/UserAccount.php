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

//TODO: add a force-reincrypt attrs method (new master key)
//TODO: Logout method. NOTE: need a $logout state where class refuses to do anything?
// I think need 2 states: unauthenticated and authneticated.
// Unauthenticated: After logout & for non-user-present tasks
// Authenticated: for normal user account stuff
// Obviously disable all the encrypted attrs and features in unauthenticated mode
//TODO: Have the session id as member variable NOTE: doing so would break VERY easily because of randomizing session

/*
 * This class is to be instantiated by the Accounts class ONLY.
 * Instantiating this class yourself is likely to lead to security problems if
 * done improperly.
 */
class UserAccount
{
    protected $username;
    protected $propername;
    protected $userid;

    public function __construct($username, $userid)
    {
        $this->username = $username;
        $this->userid = $userid;
        $this->propername = Accounts::GetProperUsername($this->username);
    }

    public function username()
    {
        return $this->username;
    }

    public function propername()
    {
        return $this->propername;
    }

    public function userid()
    {
        return $this->userid;
    }

    public function plaintextAttributeExists($key)
    {
        return $this->getPlaintextAttribute($key) !== FALSE;
    }

    public function getPlaintextAttribute($key)
    {
        global $USERDB;

        $q = $USERDB->prepare("SELECT pvalue FROM `user_data` WHERE user=:user AND pkey=:key");
        $q->bindParam(':key', $key);
        $q->bindParam(':user', $this->userid);
        $q->execute();

        if(($value = $q->fetch()) !== FALSE)
        {
            return unserialize($value['pvalue']);
        }
        return FALSE;
    }

    public function setPlaintextAttribute($key, $value)
    {
        global $USERDB;
        $value = serialize($value);

        if($this->plaintextAttributeExists($key))
        {
            $q = $USERDB->prepare("UPDATE `user_data` SET pvalue=:value 
                                    WHERE user=:user AND pkey=:key");
        }
        else
        {
            $q = $USERDB->prepare("INSERT INTO `user_data` 
                                    (user, pkey, pvalue) VALUES (:user, :key, :value)");
        }
        $q->bindParam(':user', $this->userid);
        $q->bindParam(':key', $key);
        $q->bindParam(':value', $value);
        $q->execute();

        //TODO: Error handling
    }

    public function deletePlaintextAttribute($key)
    {
        global $USERDB;

        $q = $USERDB->prepare("DELETE FROM `user_data` WHERE user=:user AND pkey=:key");
        $q->bindParam(':user', $this->userid);
        $q->bindParam(':key', $key);
        $q->execute();
    }
}
?>
