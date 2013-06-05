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

// ==================== CRYPTOGRAPHY OPTIONS ====================
//NOTE: Very few of these options can be changed after you have accumulated a database of users.
//      Choose the parameters wisely. Defaults are secure but you MUST change SITE_SPECIFIC_IV.
//
// ====== Choosing crypto parameters 101 ======
//  Hash algorithm:
//      Good choices: sha256, sha512, whirlpool, ripemd160
//  Iteration Count:
//      - The amount of hash iterations that are applied to passwords.
//      - Higher is better.
//      - Make sure you can handle the extra computation burden.
//  Hash Size - *_HASH_OCTETS constants:
//      - The checksum size in bytes. 1 byte = 8 bits.
//      - For hash functions, the security parameter is 2^(n/2) where n is the number of bits.
//      - 32 is a good choice. That's 256 bits of output, a 2^128 security factor.
//  Salt Size - *_SALT_OCTETS constants:
//      - Salt is a random value used to strengthen password hashes.
//      - Should be long enough so that no two passwords ever use the same salt
//      - 32 is a good choice.

// Constants regarding hashing passwords server-side
// None of these can be changed after website launch.
define("SERVERSIDE_HASH_ALGORITHM", "sha256");
define("SERVERSIDE_HASH_ITERATIONS", 4096);
define("SERVERSIDE_HASH_OCTETS", 64);
define("SERVERSIDE_SALT_OCTETS", 32);

// Size of all encryption and authentication keys created server-side. May be overridden by encryption algorithm.
// This should be at least the sum of the key sizes used by all of the chained ciphers.
define("SERVERSIDE_KEY_SIZE", 64);
// Server side encryption algorithm(s). Keys of the appropriate size are derived from a SERVERSIDE_KEY_SIZE-bit key.
$SERVERSIDE_ENCRYPTION_ALG = array(MCRYPT_RIJNDAEL_128, MCRYPT_TWOFISH, MCRYPT_SERPENT);
// Block cipher mode of operation
define("SERVERSIDE_ENCRYPTION_MODE", "cbc");

// Constants regarding password based key derivation server-side
// None of these can be changed after website launch.
define("SERVERSIDE_CREATEKEY_ALGORITHM", "sha512");
define("SERVERSIDE_CREATEKEY_ITERATIONS", 4096);
// Number of iterations used when creating subkeys from keys.
// Making this value large doesn't really have any positive effect.
define("SERVERSIDE_CREATESUBKEY_ITERATIONS", 2);

// Constants regarding password hashing client-side
// NOTE: SHA256 is the only hash algorithm supported by the Stanford JavaScript Crypto Library
// None of these can be changed after website launch.
define("CLIENTSIDE_HASH_ALGORITHM", "sha256");
define("CLIENTSIDE_HASH_OCTETS", 32);
// TODO: Make sure you test this parameter with multiple browsers. You may find that some execute JavaScript too slowly.
define("CLIENTSIDE_HASH_ITERATIONS", 1024);

// This should be a random string that is unique to your website. It does NOT need to be secret, just UNIQUE.
// A good source of random strings is https://defuse.ca/passgen.htm
// Cannot be changed after website launch.
define("SITE_SPECIFIC_IV", "wV5fqd3YIu9Lz3ZYl9S9vm8NKGDpEu60dPvBZKMpseF4AJHiBzTsozQpZW7LBXLE");

// Enables/Disables hashing client-side. Cannot be changed after website launch.
define("ENABLE_CLIENTSIDE_HASH", true);

// Enables/Disables server side emulation of the client-side hashing process.
// It's a good idea to enable this, to support users who browse with JavaScript disabled.
// Only turn it off if you are in a DDoS situation.
define("ENABLE_SERVERSIDE_EMULATE", true);

$RESERVED_USERS = array(
    "root", "admin", "administrator", "webmaster", "postmaster", "hostmaster",
    "google", "yahoo", "microsoft", "apple", "linux"
);

// ==================== PASSWORD POLICY ====================
define("PASSWORDPOLICY_REQUIRE_DIGIT", false);
define("PASSWORDPOLICY_REQUIRE_SYMBOL", false);
define("PASSWORDPOLICY_REQUIRE_UPPERALPHA", false);
define("PASSWORDPOLICY_REQUIRE_LOWERALPHA", false);
define("PASSWORDPOLICY_MINLENGTH", 0);
// Maximum length should not be set to anything less than 1000
define("PASSWORDPOLICY_MAXLENGTH", 1000);

// ==================== MISC ====================
define("MAX_SESSION_LIFE", 60 * 24 * 3600);
define("MIN_SESSION_LIFE", 0);

define("COOKIE_PATH", "/" );
define("COOKIE_DOMAIN", "");
define("COOKIE_SECURE", false );
define("COOKIE_HTTPONLY", TRUE);

define("SAFE_USERNAME_CHARACTERS", "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789");
define("MAX_USERNAME_LENGTH", 50);
define("MAX_EMAIL_LENGTH", 100);
define("SAFE_EMAIL_CHARACTERS", "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789@.-_+");
define("REQUIRE_EMAIL_VALIDATION", TRUE);
define("EMAIL_VALIDATION_TOKEN_OCTETS", 16);
define("EMAIL_VALIDATION_TOKEN_LIFETIME", 30 * 24 * 3600);
define("EMAIL_VALIDATION_SOURCE_ADDR", "no.reply@localhost");
define("EMAIL_VALIDATION_SUBJECT", "Email Validation");

define("EMAIL_FROM_ADDR", "noreply@localhost");

define("SEND_LOCKOUT_ALERT", TRUE);
define("LOCKOUT_ALERT_SOURCE_ADDR", "no.reply@localhost");
define("LOCKOUT_ALERT_SUBJECT", "Your Account Has Been Locked");

define("UNLOCK_TOKEN_OCTETS", 16);
define("UNLOCK_TOKEN_LIFETIME", 3600);
define("UNLOCK_TOKEN_SOURCE_ADDR", "noreply@localhost");
define("UNLOCK_TOKEN_SUBJECT", "Your Temporary Unlock Token");


define("RECORD_LOGIN_HISTORY", TRUE);
//TODO: NOTE: LOGINFAIL IPs are NOT encrypted
define("RECORD_LOGINFAIL_HISTORY", TRUE);
define("ENCRYPT_LOGIN_HISTORY_IP", TRUE);
define("ENCRYPT_LOGIN_HISTORY_AGENT", TRUE);

define("RESET_TOKEN_OCTETS", 16);
define("RESET_TOKEN_SOURCE_ADDR", "noreply@localhost");
define("RESET_TOKEN_SUBJECT", "Reset Password");
define("RESET_TOKEN_LIFETIME", 1800);

define("RESET_DISABLED_SUBJECT", "Reset Password");

// User will be locked out if the user enters the wrong password more than
// LOCKOUT_MAX_FAILURES times in a time period of LOCKOUT_TIMESPAN seconds.
// Longer = more secure, but potentially more annoying.
define("LOCKOUT_TIMESPAN", 30 * 60);
// Lower = more secure, but more annoying.
define("LOCKOUT_MAX_FAILURES", 5);
// Number of seconds the lockout lasts.
define("LOCKOUT_DURATION", 3600);
//TODO: add LOCKOUT_RESET_ON_LOGIN that, if true, failure count is reset on correct login

// Session key length in bytes
define("SESSKEY_OCTETS", 64);
// Size of key used to encrypt session data in bytes (is stored encrypted with the session key)
define("SESSDATAKEY_OCTETS", 64);

// Salt used for hashing the session key into a unique identifier for DB lookups.
// This value does not need to be globally unique or secret, it just has to be different
// than all of the other IVs and salts. The default value is fine.
define("SESSKEY_HASH_SALT", "uXMfrYCBejk4l8v7iIteETIfJEzKbDt73nhsh8DBTKvVwHXs8N7kXUBsBXspcxG");
?>
