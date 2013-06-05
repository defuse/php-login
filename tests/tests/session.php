<?php
require_once('inc/session.php');

class SessionTest
{
    private $skey = null;

    function beginTest()
    {
        $this->skey = Session::BeginSession();
    }

    function endTest()
    {
        Session::EndSession($this->skey);
    }

    // ========== TESTS ===========

    function testBogusSessionKey()
    {
        $bogusKey = bin2hex(mcrypt_create_iv(16, MCRYPT_DEV_URANDOM));
        tassert_eqs(FALSE, Session::IsValidSession($bogusKey), "Bogus session key");
    }

    function testIsValidSession()
    {
        tassert_eqs(TRUE, Session::IsValidSession($this->skey));
    }

    function testInvalidKey()
    {
        tassert_eqs(FALSE, Session::GetValue($this->skey, 'fruit'));
    }

    function testSetGetValue()
    {
        Session::SetValue($this->skey, 'fruit', 'oranges');
        $value = Session::GetValue($this->skey, 'fruit');
        tassert_eqs('oranges', $value);
    }

    function testChangeValue()
    {
        Session::SetValue($this->skey, 'fruit', 'oranges');
        Session::SetValue($this->skey, 'fruit', 'apples');
        $value = Session::GetValue($this->skey, 'fruit');
        tassert_eqs('apples', $value);
    }

    function testDeleteValue()
    {
        Session::SetValue($this->skey, 'car', 'toyota');
        Session::DeleteValue($this->skey, 'car');
        $value = Session::GetValue($this->skey, 'car');
        tassert_eqs(FALSE, $value);
    }

    function testKeyDistinction()
    {
        Session::SetValue($this->skey, 'abc', 'xyz');
        Session::SetValue($this->skey, 'def', '123');

        $value = Session::GetValue($this->skey, 'abc');
        tassert_eqs('xyz', $value);

        $value = Session::GetValue($this->skey, 'def');
        tassert_eqs('123', $value);
    }

    function testSerialization()
    {
        $pi = 3.141592653589;
        Session::SetValue($this->skey, 'pi', $pi);
        $value = Session::GetValue($this->skey, 'pi');
        tassert_eqs($pi, $value, "Double serialization");

        $ary = array(1 => "apple", 2 => $pi);
        Session::SetValue($this->skey, 'ary', $ary);
        $value = Session::GetValue($this->skey, 'ary');
        tassert_eqs($ary, $value, "Array serialization");
        tassert_eqs($ary[2], $pi, "Array[Double] serialization");
    }

    function testChangeSessionKey()
    {
        $skey = Session::BeginSession();
        Session::SetValue($skey, 'abc', 'def');
        for($i = 0; $i < 100; $i++)
        {
            $skey = Session::NewSessionKey($skey);
            $value = Session::GetValue($skey, 'abc');
            tassert_eqs('def', $value);
        }
        Session::EndSession($skey);
    }

    function testEndSession()
    {
        $skey = Session::BeginSession();
        Session::SetValue($skey, 'abc', 'def');
        Session::EndSession($skey);
        tassert_eqs(FALSE, Session::IsValidSession($skey));
        tassert_eqs(FALSE, Session::GetValue($skey, 'abc'));
    }

    function testTags()
    {
        $skey = Session::BeginSession("john");
        Session::SetValue($skey, 'wife', 'alice');
        $newskey = Session::BeginSession("john");

        tassert_eqs(FALSE, Session::GetValue($skey, 'wife'), "New session with same tag should delete old value");
        tassert_eqs(FALSE, Session::GetValue($newskey, 'wife'), "Data should not transfer to new session with same tag.");

        tassert_eqs(FALSE, Session::IsValidSession($skey), "Old session should be destroyed");
        tassert_eqs(TRUE, Session::IsValidSession($newskey));

        Session::EndSession($newskey);
    }

    function testSessionExpire()
    {
        $skey = Session::BeginSession();
        Session::SetValue($skey, 'wife', 'alice');

        Session::SetStaleTime($skey, 15);
        sleep(5);

        tassert_eqs(10, Session::GetTimeRemaining($skey), "Time remaining is 10");
        Session::RemoveStaleSessions();
        tassert_eqs('alice', Session::GetValue($skey, 'wife'), "Shouldn't expire yet");

        sleep(15); // Wait for session to expire

        tassert_eqs(FALSE, Session::GetTimeRemaining($skey), "Time remaining returns false when expired");
        tassert_eqs(FALSE, Session::GetValue($skey, 'wife'), "Data inaccessible after expire");
        tassert_eqs(FALSE, Session::IsValidSession($skey), "Invalid after expire");
        tassert_eqs(FALSE, Session::SetStaleTime($skey, 300), "SetStaleTime -> False");
        tassert_eqs(FALSE, Session::NewSessionKey($skey), "NewSessionKey -> False");
        tassert_eqs(FALSE, Session::SetValue($skey, 'a', 'b'), "SetValue -> False");
        tassert_eqs(FALSE, Session::DeleteValue($skey, 'a'), "DeleteValue -> False");
    }

}
?>
