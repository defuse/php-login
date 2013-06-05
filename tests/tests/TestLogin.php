<?php
require_once('inc/accounts.php');
require_once('inc/UserLogin.php');
require_once('inc/LoggedInUser.php');
require_once('inc/security.conf.php');
require_once('security/Crypto.php');

class TestLogin
{

    private $realuser;
    private $bogusemail;
    private $proper_realuser;
    private $realpass;
    private $session;
    private $user;

    function initialSetup()
    {
        $this->realuser = "aLIce" . mt_rand();
        $this->proper_realuser = $this->realuser;
        $this->bogusemail = "dog@invalid.invalid";
        $this->realpass = "P@s$" . mt_rand();

        $res = Accounts::CreateAccount($this->realuser, $this->bogusemail, $this->realpass, TRUE);
        EmailValidation::SetUserValidatedByName($this->realuser);
        tassert_eqs(TRUE, $res);

        $this->realuser = strtoupper($this->realuser);
    }

    function finalTeardown()
    {
        Accounts::DeleteAccount($this->realuser);
    }

    function beginTest()
    {
        $this->session = UserLogin::Login($this->realuser, $this->realpass);
        $this->user = UserLogin::GetCurrentUser($this->session);
    }

    function endTest()
    {
        UserLogin::LogOut($this->session);
        $this->user = null;
    }

    function testProperUsername()
    {
        $res = Accounts::GetProperUsername($this->realuser);
        tassert_eqs($this->proper_realuser, $res);
    }

    function testNoDuplicateUsername()
    {
        $res = Accounts::CreateAccount($this->realuser, $this->bogusemail, $this->realpass, TRUE);
        tassert_eqs(FALSE, $res);
    }

    function testCorrectPassword()
    {
        $res = Accounts::CheckPassword($this->realuser, $this->realpass);
        tassert_eqs(TRUE, $res);
    }

    function testWrongPassword()
    {
        $res = Accounts::CheckPassword($this->realuser, $this->realpass . "wrong");
        tassert_eqs(FALSE, $res);
    }

    function testWrongUsername()
    {
        $res = Accounts::CheckPassword($this->realuser . "wrong", $this->realpass);
        tassert_eqs(FALSE, $res);
    }

    function testWrongPasswordLogin()
    {
        $res = UserLogin::Login($this->realuser, $this->realpass . "wrong");
        tassert_eqs(FALSE, $res);
    }

    function testWrongUsernameLogin()
    {
        $res = UserLogin::Login($this->realuser . "wrong", $this->realpass);
        tassert_eqs(FALSE, $res);
    }

    function testCorrectLogin()
    {
        $res = UserLogin::Login($this->realuser, $this->realpass);
        tassert_eq(TRUE, $res);
    }

    function testInvalidSessionKey()
    {
        $res = UserLogin::GetCurrentUser($this->session . "wrong");
        tassert_eqs(FALSE, $res);
    }

    function testValidSessionKey()
    {
        $user = UserLogin::GetCurrentUser($this->session);
        tassert_eq(TRUE, $user);
        tassert(is_object($user));
    }

    function testCorrectUsername()
    {
        $res = $this->user->username();
        tassert_eqs(strtolower($this->realuser), $res);
    }

    function testProperCase()
    {
        $res = $this->user->propername();
        tassert_eqs($this->proper_realuser, $res);
    }

    function testInvalidEAttr()
    {
        $res = $this->user->getAttribute("n_o_t_h_i_n_g");
        tassert_eqs(FALSE, $res);
    }

    function testGetSetEAttr()
    {
        $this->user->setAttribute("one", "apple");
        $res = $this->user->getAttribute("one");
        tassert_eqs("apple", $res);

        $res = $this->user->attributeExists("one");
        tassert_eqs(TRUE, $res);
    }

    function testChangeEAttr()
    {
        $this->user->setAttribute("one", "apple");
        $this->user->setAttribute("one", "peach");
        $res = $this->user->getAttribute("one");
        tassert_eqs("peach", $res);
    }

    function testDeleteEAttr()
    {
        $this->user->setAttribute("one", "apple");
        $this->user->deleteAttribute("one");
        $res = $this->user->getAttribute("one");
        tassert_eqs(FALSE, $res);
        $res = $this->user->attributeExists("one");
        tassert_eqs(FALSE, $res);
    }

    function testEAttrSerializeFloat()
    {
        $pi = 3.141592653589;
        $this->user->setAttribute("pi", $pi);
        $res = $this->user->getAttribute("pi");
        tassert_eqs($pi, $res);
    }

    function testEAttrSerializeArray()
    {
        $pi = 3.141592653589;
        $ary = array(1 => "apple", 2 => $pi);
        $this->user->setAttribute("ary", $ary);
        $res = $this->user->getAttribute("ary");
        tassert_eqs($ary, $res);
    }

    function testInvalidPAtter()
    {
        $res = $this->user->getPlaintextAttribute("n_o_t_h_i_n_g");
        tassert_eqs(FALSE, $res);
    }

    function testGetSetPAtter()
    {
        $this->user->setPlaintextAttribute("one", "apple");
        $res = $this->user->getPlaintextAttribute("one");
        tassert_eqs("apple", $res);

        $res = $this->user->plaintextAttributeExists("one");
        tassert_eqs(TRUE, $res);
    }

    function testChangePAtter()
    {
        $this->user->setPlaintextAttribute("one", "apple");
        $this->user->setPlaintextAttribute("one", "peach");
        $res = $this->user->getPlaintextAttribute("one");
        tassert_eqs("peach", $res);
    }

    function testDeletePAtter()
    {
        $this->user->setPlaintextAttribute("one", "apple");
        $this->user->deletePlaintextAttribute("one");
        $res = $this->user->getPlaintextAttribute("one");
        tassert_eqs(FALSE, $res);
        $res = $this->user->plaintextAttributeExists("one");
        tassert_eqs(FALSE, $res);
    }

    function testPAtterSerializeFloat()
    {
        $pi = 3.141592653589;
        $this->user->setPlaintextAttribute("pi", $pi);
        $res = $this->user->getPlaintextAttribute("pi");
        tassert_eqs($pi, $res);
    }

    function testPAtterSerializeArray()
    {
        $pi = 3.141592653589;
        $ary = array(1 => "apple", 2 => $pi);
        $this->user->setPlaintextAttribute("ary", $ary);
        $res = $this->user->getPlaintextAttribute("ary");
        tassert_eqs($ary, $res);
    }

    function testPAttrEAttrDistinct()
    {
        $this->user->setPlaintextAttribute("two", "horse");
        $this->user->setAttribute("two", "zebra");
        $plain = $this->user->getPlaintextAttribute("two");
        $enc = $this->user->getAttribute("two");

        tassert_eqs("horse", $plain);
        tassert_eqs("zebra", $enc);
    }

    function testLoginTwice()
    {
        $newsession = UserLogin::Login($this->realuser,  $this->realpass);
        tassert_eq(TRUE, $newsession);

        // Should invalidate the previous session
        $user = UserLogin::GetCurrentUser($this->session);
        tassert_eqs(FALSE, $user);
        Session::EndSession($newsession);
    }

    function testChangePassword()
    {
        $res = Accounts::CreateAccount("alice", $this->bogusemail, "password1", TRUE);
        EmailValidation::SetUserValidatedByName("alice");
        tassert_eqs(TRUE, $res, "Create second account works.");

        $session = UserLogin::Login("alice", "password1");
        tassert($session, "Login works.");

        $alice = UserLogin::GetCurrentUser($session);
        $alice->setAttribute("first", "hello");
        $alice->setPlaintextAttribute("second", "goodbye");

        Accounts::ChangePassword("alice", "password1", "password2");
        $res = UserLogin::Login("alice", "password1");
        tassert_eqs(FALSE, $res, "Can't login with old password");

        UserLogin::LogOut($session);
        $session = UserLogin::Login("alice", "password2");

        $alice = UserLogin::GetCurrentUser($session);
        $res = $alice->getAttribute("first");
        tassert_eqs("hello", $res, "Encrypted attr survives password change.");
        $res = $alice->getPlaintextAttribute("second");
        tassert_eqs("goodbye", $res, "PT attr survives password change.");

        UserLogin::Logout($session);
        Accounts::DeleteAccount("alice");
    }

    function testAdministratorChangePassword()
    {
        $res = Accounts::CreateAccount("alice", $this->bogusemail, "password1", TRUE);
        EmailValidation::SetUserValidatedByName("alice");
        tassert_eqs(TRUE, $res, "Create second account works.");

        $session = UserLogin::Login("alice", "password1");
        tassert($session, "Login works.");

        $alice = UserLogin::GetCurrentUser($session);
        $alice->setAttribute("first", "hello");
        $alice->setPlaintextAttribute("second", "goodbye");

        if(ENABLE_CLIENTSIDE_HASH)
        {
            $newpass = Crypto::EmulateClientSideHash("12345", "alice");
        }
        else
        {
            $newpass = "12345";
        }

        // Automatically emulates clientside hash if enabled
        Accounts::AdministratorChangePassword("alice", "12345");

        $session = UserLogin::Login("alice", $newpass);
        tassert_eq(TRUE, $session, "Login with admin-changed pass works");
        $alice = UserLogin::GetCurrentUser($session);
        $res = $alice->getPlaintextAttribute("second");
        tassert_eqs("goodbye", $res, "PT attr survives admin change password");
        $res = $alice->getAttribute("first");
        tassert_eqs(FALSE, $res, "ENC attr is destroyed by admin change password");

        UserLogin::Logout($session);
        Accounts::DeleteAccount("alice");

    }

    //TODO break this into it's own test class
    function testUserLockout()
    {
        Accounts::CreateAccount("lockout", $this->bogusemail, "lockout", TRUE);
        EmailValidation::SetUserValidatedByName("lockout");
        $res = UserLockout::IsLockedOut("lockout");
        tassert($res === FALSE, "Not initially locked out");
        for($i = 0; $i < 2 * LOCKOUT_MAX_FAILURES; $i++)
        {
            $session = UserLogin::Login("lockout", "lockout");
        }
        UserLogin::LogOut($session); // Tags take care of removing the others
        $res = UserLockout::IsLockedOut("lockout");
        tassert($res === FALSE, "Good login doesn't increment failure count");
        for($i = 0; $i < LOCKOUT_MAX_FAILURES; $i++)
        {
            UserLogin::Login("lockout", "wrong");
        }
        $res = UserLockout::IsLockedOut("lockout");
        tassert($res === TRUE, "Locked out after LOCKOUT_MAX_FAILURES");
        $res = UserLogin::Login("lockout", "lockout", 30);
        tassert($res === FALSE, "Can't log in when locked out");
        $res = Accounts::GetUserMasterKey("lockout", "lockout");
        tassert($res === FALSE, "Can't get master key while locked out");
        $res = Accounts::ChangePassword("lockout", "lockout", "diff");
        tassert($res === FALSE, "Can't change password when locked out");
        Accounts::DeleteAccount("lockout");

        // Make sure changepassword locks out as well
        Accounts::CreateAccount("lockout2", $this->bogusemail, "lockout2", TRUE);
        EmailValidation::SetUserValidatedByName("lockout2");
        $res = UserLockout::IsLockedOut("lockout2");
        tassert($res === FALSE, "Not initially locked out");
        for($i = 0; $i < 2 * LOCKOUT_MAX_FAILURES; $i++)
        {
            $session = UserLogin::Login("lockout2", "lockout2");
        }
        UserLogin::LogOut($session); // Tags take care of removing the others
        $res = UserLockout::IsLockedOut("lockout2");
        tassert($res === FALSE, "Good login doesn't increment failure count");
        for($i = 0; $i < LOCKOUT_MAX_FAILURES; $i++)
        {
            Accounts::ChangePassword("lockout2", "wrong", "lockout2");
        }
        $res = UserLockout::IsLockedOut("lockout2");
        tassert($res === TRUE, "Locked out after LOCKOUT_MAX_FAILURES");
        Accounts::DeleteAccount("lockout2");
    }

    function testReservedUsername()
    {
        $res = Accounts::CreateAccount("root", $this->bogusemail, "root", TRUE);
        tassert_eqs(FALSE, $res);
    }
}
?>
