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
// MUST be executed from ../ (the folder containing ./inc and ./tests


require_once('inc/session.php');
require_once('tests/old/testlib.php');

$skey = bin2hex(mcrypt_create_iv(16, MCRYPT_DEV_URANDOM));
test_assert_equal_strong(Session::IsValidSession($skey), FALSE, "Invalid session");

$skey = Session::BeginSession();
echo "SKEY: " . bin2hex($skey) . "\n";

// Test IsValidSession
test_assert_equal_strong(Session::IsValidSession($skey), TRUE, "Valid session");


// Test invalid key
$invalid = Session::GetValue($skey, 'fruit');
test_assert_equal_strong($invalid, FALSE, "Invalid key");

// Test set and get value
Session::SetValue($skey, 'fruit', 'oranges');
$value = Session::GetValue($skey, 'fruit');
test_assert_equal_strong($value, 'oranges', "Valid key");

// Test change value
Session::SetValue($skey, 'fruit', 'blueberry');
$value = Session::GetValue($skey, 'fruit');
test_assert_equal_strong($value, 'blueberry', "Rewritten valid key");


// Test set and delete value
Session::SetValue($skey, 'car', 'toyota');
$value = Session::GetValue($skey, 'car');
test_assert_equal_strong($value, 'toyota', "Value before delete");
Session::DeleteValue($skey, 'car');
$value = Session::GetValue($skey, 'car');
test_assert_equal_strong($value, FALSE, "Deleted value");

// Test key distinction
Session::SetValue($skey, 'abc', 'xyz');
$value = Session::GetValue($skey, 'abc');
test_assert_equal_strong($value, 'xyz', "Key distinction");

Session::SetValue($skey, 'def', '123');
$value = Session::GetValue($skey, 'def');
test_assert_equal_strong($value, '123', "Key distinction");

// Test serialization
$pi = 3.141592653589;
Session::SetValue($skey, 'pi', $pi);
$value = Session::GetValue($skey, 'pi');
test_assert($value === $pi, "Decimal serialization");

$ary = array(1 => "apple", 2 => $pi);
Session::SetValue($skey, 'ary', $ary);
$value = Session::GetValue($skey, 'ary');
test_assert($value === $ary, "Array serialization");


// Test changing session key
Session::SetValue($skey, 'abc', 'def');
$newskey = Session::NewSessionKey($skey);
test_refute_equal_strong($newskey, $skey, "New skey different than old skey.");
test_assert_equal_strong(Session::GetValue($skey, 'abc'), FALSE, "Can't access with old sesskey");
test_assert_equal_strong(Session::GetValue($newskey, 'abc'), 'def', "Can access with new sesskey");
$skey = $newskey;

// End the session
Session::EndSession($skey);

test_assert_equal_strong(Session::IsValidSession($skey), FALSE, "Invalid session");

// Test reading values after ending session
$value = Session::GetValue($skey, 'fruit');
test_assert_equal_strong($value, FALSE, "Reading value after session end");

// Test tags

$skey = Session::BeginSession("john");
Session::SetValue($skey, 'wife', 'alice');
$value = Session::GetValue($skey, 'wife');
test_assert_equal_strong($value, 'alice', "Read/write data works");

$newskey = Session::BeginSession("john");
$value = Session::GetValue($skey, 'wife');
test_assert_equal_strong($value, FALSE, "New session with same tag obliterates old key");
$value = Session::GetValue($newskey, 'wife');
test_assert_equal_strong($value, FALSE, "Data not transfered to new key with tag.");

Session::EndSession($skey);
Session::EndSession($newskey);

// Test stale sessions

$skey = Session::BeginSession();
Session::SetValue($skey, 'wife', 'alice');
$value = Session::GetValue($skey, 'wife');
test_assert($value === 'alice', "Read/write data works");

// Set to delete in 15 seconds
Session::SetStaleTime($skey, 15);
echo "Waiting a while...\n";
sleep(5);
$value = Session::GetTimeRemaining($skey);
test_assert($value === 10, "10 seconds left");
Session::RemoveStaleSessions();
$value = Session::GetValue($skey, 'wife');
test_assert($value === 'alice', "Not deleted yet");
echo "Waiting for stale timeout...\n";
sleep(15);
Session::RemoveStaleSessions();
$value = Session::GetTimeRemaining($skey);
test_assert($value === FALSE, "Time remainging returns false on invalid session.");
$value = Session::GetValue($skey, 'wife');
test_assert($value === FALSE, "Deleted after stale timeout");


// Test that all methods return false when the session expires
$skey = Session::BeginSession();
Session::SetValue($skey, 'wife', 'alice');
Session::SetStaleTime($skey, 1);
sleep(2);
$value = Session::SetStaleTime($skey, 100000);
test_assert($value === FALSE, "SetStaleTime -> FALSE");

$skey = Session::BeginSession();
Session::SetValue($skey, 'wife', 'alice');
Session::SetStaleTime($skey, 1);
sleep(2);
$value = Session::GetTimeRemaining($skey);
test_assert($value === FALSE, "GetTimeRemaining -> FALSE");

$skey = Session::BeginSession();
Session::SetValue($skey, 'wife', 'alice');
Session::SetStaleTime($skey, 1);
sleep(2);
$value = Session::NewSessionKey($skey);
test_assert($value === FALSE, "NewSessionKey -> FALSE");

$skey = Session::BeginSession();
Session::SetValue($skey, 'wife', 'alice');
Session::SetStaleTime($skey, 1);
sleep(2);
$value = Session::IsValidSession($skey);
test_assert($value === FALSE, "IsValidSession -> FALSE");

$skey = Session::BeginSession();
Session::SetValue($skey, 'wife', 'alice');
Session::SetStaleTime($skey, 1);
sleep(2);
$value = Session::SetValue($skey, 'wife', 'nobody');
test_assert($value === FALSE, "SetValue -> FALSE");

$skey = Session::BeginSession();
Session::SetValue($skey, 'wife', 'alice');
Session::SetStaleTime($skey, 1);
sleep(2);
$value = Session::DeleteValue($skey, 'wife');
test_assert($value === FALSE, "DeleteValue -> FALSE");

$skey = Session::BeginSession();
Session::SetValue($skey, 'wife', 'alice');
Session::SetStaleTime($skey, 1);
sleep(2);
$value = Session::GetValue($skey, 'wife');
test_assert($value === FALSE, "GetValue -> FALSE");






Session::EndSession($skey);


test_allpass();
?>
