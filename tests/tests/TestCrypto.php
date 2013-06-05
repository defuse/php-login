<?php
require_once('inc/security.conf.php');
require_once('security/Crypto.php');

set_time_limit(300);

class TestCrypto
{
    function testEncryptDecrypt()
    {
        $ct = Crypto::Encrypt("applesauce", "apple");
        $pt = Crypto::Decrypt($ct, "apple");
        tassert("applesauce" === $pt, "Encrypt and Decrypt");
    }

    function testInvalidKey()
    {
        $ct = Crypto::Encrypt("applesauce", "apple");
        $badkey = "apples";
        tassert(Crypto::Decrypt($ct, $badkey) === FALSE, "Bad key.");
    }

    function testAlteredHMAC()
    {
        $ct = Crypto::Encrypt("applesauce", "apple");
        $hmac_manip = $ct;
        $hmac_manip[0] = chr((ord($hmac_manip[0]) + 1) % 256);
        tassert(Crypto::Decrypt($hmac_manip, "apple") === FALSE, "HMAC manipulation.");
    }

    function testAlteredIV()
    {
        $ct = Crypto::Encrypt("applesauce", "apple");
        $hmacsize = strlen(hash_hmac(SERVERSIDE_HASH_ALGORITHM, '', '', true));
        $iv_manip = $ct;
        $iv_manip[$hmacsize+1] = chr((ord($iv_manip[$hmacsize+1]) + 1) % 256);
        tassert(Crypto::Decrypt($iv_manip, "apple") === FALSE, "IV manipulation.");
    }

    function testAlteredCiphertext()
    {
        $ct = Crypto::Encrypt("applesauce", "apple");
        $hmacsize = strlen(hash_hmac(SERVERSIDE_HASH_ALGORITHM, '', '', true));
        $ct_manip = $ct;
        $ct_manip[$hmacsize+1] = chr((ord($ct_manip[$hmacsize+1]) + 1) % 256);
        tassert(Crypto::Decrypt($ct_manip, "apple") === FALSE, "CT manipulation.");
    }

    function testIVWorks()
    {
        $plaintext = "";
        $key = "";
        $a = Crypto::Encrypt($plaintext, $key);
        $b = Crypto::Encrypt($plaintext, $key);
        tassert($a != $b, "Unique encryption.");
    }

    function testPBKDF2()
    {
        // ========== Test PBKDF2 ========== 
        //Test vector source: https://www.ietf.org/rfc/rfc6070.txt

        $pbkdf_vectors = array(
            array(
                'algorithm' => 'sha1', 
                'password' => "password", 
                'salt' => "salt", 
                'iterations' => 1, 
                'keylength' => 20, 
                'output' => "0c60c80f961f0e71f3a9b524af6012062fe037a6" 
                ),
            array(
                'algorithm' => 'sha1', 
                'password' => "password", 
                'salt' => "salt", 
                'iterations' => 2, 
                'keylength' => 20, 
                'output' => "ea6c014dc72d6f8ccd1ed92ace1d41f0d8de8957"
                ),
            array(
                'algorithm' => 'sha1', 
                'password' => "password", 
                'salt' => "salt", 
                'iterations' => 4096, 
                'keylength' => 20, 
                'output' => "4b007901b765489abead49d926f721d065a429c1"
                ),
            array(
                'algorithm' => 'sha1', 
                'password' => "password", 
                'salt' => "salt", 
                'iterations' => 7613, 
                'keylength' => 769, 
                'output' => "465b6262d40836a5abc6c17cbe739256f878f566c86b4bd876e910286a14ec7e6d490871fb585b331852225a76f11c4cc1a15b4e117f0a22816f55079353e6836fb26f9aabd91c0d77890c9f853dd5e1b0de7c7bc9ec49ab21db6688ba77526fb22cc9f7bcd414401594b7bf5837bbefe2833b79f7d572cd0a53dfe59b74018f0463e7b64bb256dc619f22f3c4d402d51c635550418de618b8098d98d627656643b45420ed1a4cf9287f414b909bc39054543fd34da5d7ecaf5def398fa11dabd9bcc355e0190115c5ddc6e4ac0acedccd78cf83d08a18069ac0560630bc4b2fab77dc569058f35d21d720456c7cf42aed0c61cba2880b5b284179df36ab3050815bd4e7b49aa8c3876c85d4db6a70d8b1e4411c070a6cece85634f8863dd774f07708e7c381f2fa2645019d92f7efc4fe342156ea4ff0ab28e6a3226387ba5cd7da33e43e3e86f5257de478a8901d4ed7e5622a35f1739bc86dee4616577f0322d9e0ed6f0a7c9c675e36508d4c80b8b0c651aaf3af8b4b139fc8e40bdfa3153b2f6c5b4da62475dceb97efc557ee03654bfbf0140a3fa39bf979ab10e819bf608e63dbbfc573359778dc568119b482c0208129c9c987aa5670cd32f25d8787da7f26236e180e6a79f98aaf8c34ff83d55b8e22df6856559cdea1996d408c484eb16858c24c3cd9b8818896df707b29b27e56862f9a6b32d0998c3daa8ae1a429c3752fc498513888ed3dc1607e4749c8e146fc55e683adf17295a9ac015a92c85101db520f09b7affede169aeb8608d328860f516126e3274c38e317f9aaa7037e01279544281d43d9a88e5e0593a67bb15aebeb08312db706227f561a8607ffdd9562a7f13c5ecf79b7cfc6873be1a96af7baf1adefcb0d4446f981b44fe12d5a77a7d520d0d321a568408960e7e00066f4ab5200c14b0415aa51a49818ca47a8d7836aa017a2d63f2fb5bfff5ae2fb548b3088546864d2cb044d3aef6d9928d72df9eff842a01daf94e03f27ca9d06b14fdfac9c528a4a52e8788c338f11673c32cd60f060608b83a80e708ec4d3ecdb0a6a5086eb245c38d87589d272d590"
                ),
            array(
                'algorithm' => 'sha1', 
                'password' => "passwordPASSWORDpassword", 
                'salt' => "saltSALTsaltSALTsaltSALTsaltSALTsalt", 
                'iterations' => 4096, 
                'keylength' => 25, 
                'output' => "3d2eec4fe41c849b80c8d83662c0e44a8b291a964cf2f07038"
                ), 
            array(
                'algorithm' => 'sha1', 
                'password' => "pass\0word", 
                'salt' => "sa\0lt", 
                'iterations' => 4096, 
                'keylength' => 16, 
                'output' => "56fa6aa75548099dcc37d7f03425e0c3"
                ),            
        );

        foreach($pbkdf_vectors as $test)
        {
            $realOut = bin2hex(Crypto::pbkdf2($test['algorithm'], $test['password'], $test['salt'], 
                                                            $test['iterations'], $test['keylength']));

            tassert($realOut === $test['output'], "PBKDF Vector");
            if($realOut !== $test['output'])
            {
                echo "FAIL: PBKDF VECTOR:\n";
                print_r($test);
                echo "\n\nGot: $realOut\n\n";
            }
        }

    }

    function testHashPassword()
    {
        $hash = Crypto::HashPassword("password");
        tassert(Crypto::ValidatePassword("password", $hash), "Correct password");

        $hash = Crypto::HashPassword("apple");
        tassert(!Crypto::ValidatePassword("orange", $hash), "Different passwords");
    }

    function testHashSaltModification()
    {
        $hash = Crypto::HashPassword("password");
        $hash[0] = "z";
        tassert(!Crypto::ValidatePassword("password", $hash), "Salt modification");
    }

    function testHashModification()
    {
        $hash = Crypto::HashPassword("password");
        $hash[strlen($hash) - 1] = "z";
        tassert(!Crypto::ValidatePassword("password", $hash), "Hash modification");
    }

    function testHashesAreDifferent()
    {
        $hash1 = Crypto::HashPassword("password");
        $hash2 = Crypto::HashPassword("password");
        tassert($hash1 != $hash2, "Overall hash not equal.");
        tassert(substr($hash1, 0, 2 * SERVERSIDE_SALT_OCTETS) != substr($hash2, 0, 2 * SERVERSIDE_SALT_OCTETS), "Salt part not equal.");
        tassert(substr($hash1, 2 * SERVERSIDE_SALT_OCTETS, 2 * SERVERSIDE_HASH_OCTETS) != substr($hash2, 2 * SERVERSIDE_SALT_OCTETS, 2 * SERVERSIDE_HASH_OCTETS), "Hash part not equal.");
    }

    function testCreateKeyIsSame()
    {
        $key1 = Crypto::CreateKey("password", "testing");
        $key2 = Crypto::CreateKey("password", "testing");
        tassert($key1 == $key2, "CreateKey same everything.");
    }

    function testCreateKeyDiffPurpose()
    {
        $key1 = Crypto::CreateKey("password", "testingONE");
        $key2 = Crypto::CreateKey("password", "testingTWO");
        tassert($key1 != $key2, "CreateKey different purpose.");
    }

    function testCreateKeyDiffPassword()
    {
        $key1 = Crypto::CreateKey("passwordONE", "testing");
        $key2 = Crypto::CreateKey("passwordTWO", "testing");
        tassert($key1 != $key2, "CreateKey different password.");
    }

}

?>
