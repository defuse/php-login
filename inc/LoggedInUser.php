<?php
require_once('inc/UserAccount.php');
require_once('inc/dblogin.php');
require_once('security/Crypto.php');

class LoggedInUser extends UserAccount
{
    protected $masterkey;

    public function __construct($username, $userid, $masterkey)
    {
        parent::__construct($username, $userid);
        $this->masterkey = $masterkey;
    }

    public function getAttribute($key)
    {
        global $USERDB;

        $q = $USERDB->prepare("SELECT pvalue FROM `user_encrypted_data` WHERE user=:user AND pkey=:key");
        $q->bindParam(':key', $key);
        $q->bindParam(':user', $this->userid);
        $q->execute();

        if(($value = $q->fetch()) !== FALSE)
        {
            $value = $value['pvalue'];
            return unserialize(Crypto::Decrypt($value, $this->masterkey));
        }
        return FALSE;
    }

    public function setAttribute($key, $value)
    {
        global $USERDB;

        $value = Crypto::Encrypt(serialize($value), $this->masterkey);

        if($this->attributeExists($key))
        {
            $q = $USERDB->prepare("UPDATE `user_encrypted_data` SET pvalue=:value 
                                    WHERE user=:user AND pkey=:key");
        }
        else
        {
            $q = $USERDB->prepare("INSERT INTO `user_encrypted_data` 
                                    (user, pkey, pvalue) VALUES (:user, :key, :value)");
        }
        $q->bindParam(':user', $this->userid);
        $q->bindParam(':key', $key);
        $q->bindParam(':value', $value);
        $q->execute();

        //TODO: Error handling
    }

    public function deleteAttribute($key)
    {
        global $USERDB;

        $q = $USERDB->prepare("DELETE FROM `user_encrypted_data` WHERE user=:user AND pkey=:key");
        $q->bindParam(':user', $this->userid);
        $q->bindParam(':key', $key);
        $q->execute();
    }

    public function attributeExists($key)
    {
        return $this->getAttribute($key) !== FALSE;
    }

}
?>
