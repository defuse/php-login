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
require_once('inc/log.php');

//TODO: Syslog on ciphertext tampering
//TODO: Document cipher chaining
//TODO: BUG??? Why does ciphertext size vary so much

/*
 * Implements cryptographic primitives that are common to web applications.
 */
class Crypto
{
    private function __construct() {}

    /*
     * Returns a random binary string of length $octets bytes.
     */
    public static function SecureRandom($octets)
    {
        return mcrypt_create_iv($octets, MCRYPT_DEV_URANDOM);
    }
    
    /*
     * Converts a string of hexadecimal characters (uppercase or lowercase) to binary.
     */
    public static function hex2bin($hex)
    {
        return pack("H*", $hex);
    }

    /*
     * Encrypts and authenticates a string.
     * $plaintext - The text to encrypt.
     * $key - The key used to encrypt. Must be secret (obviously).
     * $key can be a binary string of any size, but it should be at least the sum
     * of the sizes of the keys of the algorithms that are chained.
     * Returns: The ciphertext, in *binary* format.
     */
    public static function Encrypt($plaintext, $key, $alg = null, $auth = TRUE)
    {
        /* 
         * Implementation note: This is not the best way to implement cascading/cipher chaining.
         * See p. 361 of Applied Cryptography. This is Inner-CBC and Bruce reccomends Outer-CBC.
         * Although it is at least as secure as single encryption it may not provide much of
         * a benefit when the same algorithm is chained. When multple algorithms in use
         * I *suspect* it is significantly more secure since the algorithms will have
         * very different differential characteristics.
         */
        global $SERVERSIDE_ENCRYPTION_ALG;
        if(is_null($alg))
            $alg = $SERVERSIDE_ENCRYPTION_ALG;

        // Cipher chaining
        if(is_array($alg))
        {
            $ciphertext = $plaintext;
            $i = 0;
            for($i = 0; $i < count($alg) - 1; $i++)
            {
                // Salt the key with the chain 'level' number so that keys are unique
                // even when the data is encrypted with the same algorithm multiple times.
                // Don't authenticate intermediate ciphertexts
                $ciphertext = self::Encrypt($ciphertext, $key . decbin($i) , $alg[$i], FALSE);
            }
            // Authenticate the last ciphertext
            return self::Encrypt($ciphertext, $key . $i, $alg[$i], TRUE);
        }
        else
        {
            // Ciphertext format [____HMAC____][____IV____][____CIPHERTEXT____]
            $crypt = mcrypt_module_open($alg, "", SERVERSIDE_ENCRYPTION_MODE, "");
            $keysize = mcrypt_enc_get_key_size($crypt);
            $ivsize = mcrypt_enc_get_iv_size($crypt);

            // Each cipher has a different key
            $ekey = self::CreateSubkey($key, "text/encryption:" . $alg, $keysize);
            $iv = self::SecureRandom($ivsize);

            // Pad the plaintext (PKCS #7)
            $block = mcrypt_enc_get_block_size($crypt);
            $pad = $block - (strlen($plaintext) % $block);
            $plaintext .= str_repeat(chr($pad), $pad);

            mcrypt_generic_init($crypt, $ekey, $iv);
            $ciphertext = $iv . @mcrypt_generic($crypt, $plaintext); // Suppress emtpy string warning
            mcrypt_generic_deinit($crypt);
            mcrypt_module_close($crypt);

            if($auth)
            {
                $akey = self::CreateSubkey($key, "text/authentication", SERVERSIDE_KEY_SIZE);
                $auth = hash_hmac(SERVERSIDE_HASH_ALGORITHM, $ciphertext, $akey, true);
                $ciphertext = $auth . $ciphertext;
            }

            return $ciphertext;
        }
    }

    /*
     * Decrypts and authenticates a string that was encrypted with Encrypt
     * $ciphertext - The ciphertext, in binary format, as returned from Encrypt.
     * $key - The key used to encrypt the ciphertext.
     * Returns: The plaintext. Returns boolean FALSE if the ciphertext has been altered.
     */
    public static function Decrypt($ciphertext, $key, $alg = null, $auth = TRUE)
    {
        global $SERVERSIDE_ENCRYPTION_ALG;
        if(is_null($alg))
            $alg = $SERVERSIDE_ENCRYPTION_ALG;

        if(is_array($alg))
        {
            $plaintext = self::Decrypt($ciphertext, $key . (count($alg) - 1), $alg[count($alg) - 1], TRUE);
            if($plaintext === FALSE)
                return FALSE;

            for($i = count($alg) - 2; $i >= 0; $i--)
            {
                $plaintext = self::Decrypt($plaintext, $key . $i, $alg[$i], FALSE);
            }
            return $plaintext;
        }
        else
        {
            // Ciphertext format [____HMAC____][____IV____][____CIPHERTEXT____]
            //TODO: handle strlen < iv size and shit

            if($auth)
            {
                $hmacsize = strlen(hash_hmac(SERVERSIDE_HASH_ALGORITHM, '', '', true));

                // Get the HMAC from the front
                $hmac = substr($ciphertext, 0, $hmacsize);
                // Remove the HMAC on the front
                $ciphertext = substr($ciphertext, $hmacsize);

                $akey = self::CreateSubkey($key, "text/authentication", SERVERSIDE_KEY_SIZE);
            }
            // Check if the ciphertext has been tampered with
            if($auth === FALSE || $hmac === hash_hmac(SERVERSIDE_HASH_ALGORITHM, $ciphertext, $akey, true))
            {
                $crypt = mcrypt_module_open($alg, "", SERVERSIDE_ENCRYPTION_MODE, "");
                $keysize = mcrypt_enc_get_key_size($crypt);
                $ivsize = mcrypt_enc_get_iv_size($crypt);

                $ekey = self::CreateSubkey($key, "text/encryption:" . $alg, $keysize);

                // Get the IV off the front
                $iv = substr($ciphertext, 0, $ivsize);
                $ciphertext = substr($ciphertext, $ivsize);
                
                // Decrypt the ciphertext
                mcrypt_generic_init($crypt, $ekey, $iv);
                $plaintext = mdecrypt_generic($crypt, $ciphertext);
                mcrypt_generic_deinit($crypt);
                mcrypt_module_close($crypt);

                // Unpad the plaintext
                $pad = ord($plaintext[strlen($plaintext) - 1]);
                $plaintext = substr($plaintext, 0, strlen($plaintext) - $pad);

                return $plaintext;
            }
            else
            {
                // Refuse to decrypt the data if it has been tampered with.
                Log::LogError("Ciphertext Tampering", LOG_LEVEL_WARNING);
                return FALSE;
            }
        }
    }

    /*
     * Emulates what should be done in client-side scripts. For users who browse with JavaScript disabled.
     * $password - The password.
     * $username - The account username.
     * Returns: The hashed password that would have been sent by JavaScript if it was enabled.
     */
    public static function EmulateClientSideHash($password, $username)
    {
        $salt = strtolower($username) . SITE_SPECIFIC_IV;
        return bin2hex(self::pbkdf2(CLIENTSIDE_HASH_ALGORITHM, $password, $salt, CLIENTSIDE_HASH_ITERATIONS, CLIENTSIDE_HASH_OCTETS));
    }

    /* 
     * Hashes a password using PBKDF2 with HMAC-SHA256 and a random salt.
     * $password - The password to be hashed.
     * Returns: SERVERSIDE_SALT_OCTETS * 2 hex characters of salt prepended to a SERVERSIDE_HASH_OCTETS * 2 hex character hash. 
     */
    public static function HashPassword($password)
    {
        $salt = bin2hex(mcrypt_create_iv(SERVERSIDE_SALT_OCTETS, MCRYPT_DEV_URANDOM));
        $hash = bin2hex(self::pbkdf2(SERVERSIDE_HASH_ALGORITHM, $password, $salt, SERVERSIDE_HASH_ITERATIONS, SERVERSIDE_HASH_OCTETS)); 

        //store the salt and hash in the same string, so only 1 DB column is needed
        $final = $salt . $hash; 
        return $final;
    }

    /*
     * Validates a password hashed with the 'HashPassword' function.
     * This function takes care of handling salt automatically.
     * $password - The password to be verified.
     * $correctHash - The hash of the known-to-be-correct password.
     * Returns: True if the hash is valid, false if not.
     */
    public static function ValidatePassword($password, $correctHash)
    {
        $saltLength = 2 * SERVERSIDE_SALT_OCTETS;
        $salt = substr($correctHash, 0, $saltLength); 
        $validHash = substr($correctHash, $saltLength, 2 * SERVERSIDE_HASH_OCTETS);

        $testHash = bin2hex(self::pbkdf2(SERVERSIDE_HASH_ALGORITHM, $password, $salt, SERVERSIDE_HASH_ITERATIONS, SERVERSIDE_HASH_OCTETS));

        //if the hashes are exactly the same, the password is valid
        return $testHash === $validHash;
    }

    
    /*
     * Creates a cryptographic hash of some data.
     * $data - Data to hash.
     * $salt - Salt for the hash.
     * Returns: Checksum in the form of a *binary* string.
     */
    public static function HashData($data, $salt = "")
    {
        return hash_hmac(SERVERSIDE_HASH_ALGORITHM, $data, $salt, true);
    }

    /*
     * Creates an encryption key from a password.
     * $password - The password.
     * $purpose - A string unique to the key's purpose. Like a salt.
     * $octets - The length of the key in bytes.
     * Returns: The key in binary.
     */
    public static function CreateKey($password, $purpose, $octets = 32, $extrasalt = "")
    {
        return self::pbkdf2(SERVERSIDE_CREATEKEY_ALGORITHM, $password, $purpose . '#' . $extrasalt, SERVERSIDE_CREATEKEY_ITERATIONS, $octets);
    }

    /*
     * Creates a subkey (special purpose key) from a master key.
     * $masterkey - The key the subkey will be based on.
     * $purpose - A unique-per-purpose string. (MUST BE UNIQUE: The key is actually a function of this string).
     * $octets - The size in bytes of the key to return.
     * $extrasalt - Optional extra salt to add to the key generation process.
     * Returns: $octets-byte binary key that is a function of $masterkey, $purpose, and $extrasalt
     * NOTE: Use CreateKey if creating an encryption key from a password.
     */
    public static function CreateSubkey($masterkey, $purpose, $octets = 32, $extrasalt = "")
    {
        return self::pbkdf2(SERVERSIDE_CREATEKEY_ALGORITHM, 
                            $masterkey, 
                            $purpose . "#" . $extrasalt, 
                            SERVERSIDE_CREATESUBKEY_ITERATIONS
                            , 
                            $octets);
    }
        
    /*
     * PBKDF2 key derivation function as defined by RSA's PKCS #5: https://www.ietf.org/rfc/rfc2898.txt
     * $algorithm - The hash algorithm to use. Recommended: SHA256
     * $password - The password.
     * $salt - A salt that is unique to the password.
     * $count - Iteration count. Higher = better. Recommended: At least 1024.
     * $key_length - The length of the derived key in BYTES.
     * Returns: A $key_length-byte key derived from the password and salt (in binary).
     *
     * Test vectors can be found here: https://www.ietf.org/rfc/rfc6070.txt
     */
    public static function pbkdf2($algorithm, $password, $salt, $count, $key_length)
    {
        $algorithm = strtolower($algorithm);
        if(!in_array($algorithm, hash_algos(), true))
            die('PBKDF2 ERROR: Invalid hash algorithm.');
        if($count < 0 || $key_length < 0)
            die('PBKDF2 ERROR: Invalid parameters.');
        if($key_length > 4294967295)
            die('PBKDF2 ERROR: Derived key too long.');

        $hLen = strlen(hash($algorithm, "", true));
        $numBlocks = (int)ceil((double)$key_length / $hLen);

        $output = "";
        for($i = 1; $i <= $numBlocks; $i++)
        {
            $output .= self::pbkdf2_f($password, $salt, $count, $i, $algorithm, $hLen);
        }

        return substr($output, 0, $key_length);
    }

    /*
     * The pseudorandom function used by PBKDF2.
     * Definition: https://www.ietf.org/rfc/rfc2898.txt
     */
    private static function pbkdf2_f($password, $salt, $count, $i, $algorithm, $hLen)
    {
        //$i encoded as 4 bytes, big endian.
        $last = $salt . chr(($i >> 24) % 256) . chr(($i >> 16) % 256) . chr(($i >> 8) % 256) . chr($i % 256);
        $xorsum = "";
        for($r = 0; $r < $count; $r++)
        {
            $u = hash_hmac($algorithm, $last, $password, true);
            $last = $u;
            if(empty($xorsum))
                $xorsum = $u;
            else
            {
                for($c = 0; $c < $hLen; $c++)
                {
                    $xorsum[$c] = chr(ord(substr($xorsum, $c, 1)) ^ ord(substr($u, $c, 1)));
                }
            }
        }
        return $xorsum;
    }
}
?>
