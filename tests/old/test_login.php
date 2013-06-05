<?php
    //TODO: Test various combinations of account being deleted
    //TODO: Test various password change scenarios
    //TODO: Test password policy and username policy

    require_once('tests/old/testlib.php');
    require_once('inc/accounts.php');
    require_once('inc/LoggedInUser.php');
    require_once('inc/UserLogin.php');
    require_once('inc/session.php');
    require_once('inc/security.conf.php');
    require_once('inc/accounts.php');

    $bogusemail = "dog@invalid.invalid";
    $realuser = "aLIce" . mt_rand();
    $proper_realuser = $realuser;
    $realpass = "P@s$" . mt_rand();

    $res = Accounts::CreateAccount($realuser, $bogusemail, $realpass, TRUE);
    EmailValidation::SetUserValidatedByName($realuser);
    test_assert($res === TRUE, "Create account");

    $realuser = strtoupper($realuser); // Everything should be case insensitive

    $res = Accounts::GetProperUsername($realuser);
    test_assert($res === $proper_realuser, "Correct case is saved");

    $res = Accounts::CreateAccount($realuser, $bogusemail, $realpass, TRUE);
    EmailValidation::SetUserValidatedByName($realuser);
    test_assert($res === FALSE, "No duplicates");

    $res = Accounts::CheckPassword($realuser, $realpass);
    test_assert($res === TRUE, "Correct password");

    $res = Accounts::CheckPassword($realuser, $realpass . "wrong");
    test_assert($res === FALSE, "Wrong password");

    $res = Accounts::CheckPassword($realuser . "wrong", $realpass);
    test_assert($res === FALSE, "Wrong username");

    $res = UserLogin::Login($realuser, $realpass . "wrong");
    test_assert($res === FALSE, "Wrong password (Login)");

    $res = UserLogin::Login($realuser . "wrong", $realpass);
    test_assert($res === FALSE, "Wrong username (Login)");
    $session = UserLogin::Login($realuser, $realpass);
    test_assert($session == TRUE, "Correct Login");

    $res = UserLogin::GetCurrentUser($session . "wrong");
    test_assert($res === FALSE, "Invalid session key");

    $user = UserLogin::GetCurrentUser($session);
    test_assert($user == TRUE, "Valid session");
    test_assert(is_object($user), "User is object");

    $res = $user->username();
    test_assert($res === strtolower($realuser), "Correct username.");

    // --- encrypted attributes ---
    $res = $user->getAttribute("n_o_t_h_i_n_g");
    test_assert($res === FALSE, "Invalid encrypted attribute");

    $user->setAttribute("one", "apple");
    $res = $user->getAttribute("one");
    test_assert($res === "apple", "Set and get encrypted attribute");

    $res = $user->attributeExists("one");
    test_assert($res === TRUE, "Attr exists");

    $user->setAttribute("one", "peach");
    $res = $user->getAttribute("one");
    test_assert($res === "peach", "Reset attr");

    $user->deleteAttribute("one");
    $res = $user->getAttribute("one");
    test_assert($res === FALSE, "Delete attr");

    $pi = 3.141592653589;
    $user->setAttribute("pi", $pi);
    $res = $user->getAttribute("pi");
    test_assert($res === $pi, "Serialize floating point");

    $ary = array(1 => "apple", 2 => $pi);
    $user->setAttribute("ary", $ary);
    $res = $user->getAttribute("ary");
    test_assert($res === $ary, "Serialize array");


    // --- plaintext attributes ---
    $res = $user->getPlaintextAttribute("n_o_t_h_i_n_g");
    test_assert($res === FALSE, "Invalid encrypted attribute");

    $user->setPlaintextAttribute("one", "apple");
    $res = $user->getPlaintextAttribute("one");
    test_assert($res === "apple", "Set and get encrypted attribute");

    $res = $user->plaintextAttributeExists("one");
    test_assert($res === TRUE, "Attr exists");

    $user->setPlaintextAttribute("one", "peach");
    $res = $user->getPlaintextAttribute("one");
    test_assert($res === "peach", "Reset attr");

    $user->deletePlaintextAttribute("one");
    $res = $user->getPlaintextAttribute("one");
    test_assert($res === FALSE, "Delete PT attr");

    $pi = 3.141592653589;
    $user->setPlaintextAttribute("pi", $pi);
    $res = $user->getPlaintextAttribute("pi");
    test_assert($res === $pi, "Serialize floating point");

    $ary = array(1 => "apple", 2 => $pi);
    $user->setPlaintextAttribute("ary", $ary);
    $res = $user->getPlaintextAttribute("ary");
    test_assert($res === $ary, "Serialize array");

    // Make sure plaintext and encrypted attrs are distinct
    $user->setPlaintextAttribute("two", "horse");
    $user->setAttribute("two", "zebra");
    $plain = $user->getPlaintextAttribute("two");
    test_assert($plain === "horse", "PT not overwritten by ENC");

    $user->setPlaintextAttribute("two", "horse");
    $enc = $user->getAttribute("two");
    test_assert($enc === "zebra", "ENC not overwritten by PT");

    test_assert($enc != $plain, "Encrypted attrs and plaintext attrs have distinct keyspace");

    Session::EndSession($session);

    // Test kill session with tag
    $session = UserLogin::Login($realuser, $realpass);
    test_assert($session == TRUE, "Correct Login");
    $user = UserLogin::GetCurrentUser($session);
    test_assert(is_object($user), "Getting user works");

    // This should obliterate the previous session
    $newsession = UserLogin::Login($realuser, $realpass);
    test_assert($newsession == TRUE, "Correct Login");
    $user = UserLogin::GetCurrentUser($newsession);
    test_assert(is_object($user), "Getting user with new session works");

    // Make sure the old session is useless
    $user = UserLogin::GetCurrentUser($session);
    test_assert($user === FALSE, "Old session is obliterated");

    Session::EndSession($newsession);
    // NOTE: This the session data for $session will be left in the database because
    // it gets obliterated through the TAG mechanism (which doesn't delete session data)
    Session::EndSession($session);

    $session = UserLogin::Login($realuser, $realpass);
    test_assert($session == TRUE, "Login works");
    Accounts::DeleteAccount($realuser); 
    $user = UserLogin::GetCurrentUser($session);
    test_assert($user === FALSE, "Get current user fails after delete account");
    $newsession = UserLogin::Login($realuser, $realpass);
    test_assert($newsession === FALSE, "Login fails after deleting account");

    Session::EndSession($session);

    // Test Change Password functions
    $res = Accounts::CreateAccount("alice", $bogusemail, "password1", TRUE);
    EmailValidation::SetUserValidatedByName("alice");
    test_assert($res === TRUE, "Create second account works.");

    $session = UserLogin::Login("alice", "password1");
    test_assert($session, "Login works.");

    $alice = UserLogin::GetCurrentUser($session);
    $alice->setAttribute("first", "hello");
    $alice->setPlaintextAttribute("second", "goodbye");

    Accounts::ChangePassword("alice", "password1", "password2");
    $res = UserLogin::Login("alice", "password1");
    test_assert($res === FALSE, "Can't login with old password");

    UserLogin::LogOut($session);
    $session = UserLogin::Login("alice", "password2");

    $alice = UserLogin::GetCurrentUser($session);
    $res = $alice->getAttribute("first");
    test_assert($res === "hello", "Encrypted attr survives password change.");
    $res = $alice->getPlaintextAttribute("second");
    test_assert($res === "goodbye", "PT attr survives password change.");

    // Test administrator change password
    if(ENABLE_CLIENTSIDE_HASH)
    {
        $newpass = Crypto::EmulateClientSideHash("12345", "alice");
    }
    else
    {
        $newpass = "12345";
    }
    //AdministratorChangePassword automatically emulates clientside hash
    Accounts::AdministratorChangePassword("alice", "12345");
    $session = UserLogin::Login("alice", "password2");
    test_assert($session === FALSE, "Login with old password after administrator change fails.");
    $session = UserLogin::Login("alice", $newpass);
    test_assert($session != FALSE, "Login with new administrator-changed password works.");
    $alice = UserLogin::GetCurrentUser($session);
    $res = $alice->getPlaintextAttribute("second");
    test_assert($res === "goodbye", "PT attr survives administrator password change.");
    $res = $alice->getAttribute("first");
    test_assert($res === FALSE, "Encrypted attr does not survive administrator password change.");

    UserLogin::LogOut($session);
    Accounts::DeleteAccount("alice");

    Accounts::CreateAccount("lockout", $bogusemail, "lockout", TRUE);
    EmailValidation::SetUserValidatedByName("lockout");
    $res = UserLockout::IsLockedOut("lockout");
    test_assert($res === FALSE, "Not initially locked out");
    for($i = 0; $i < 2 * LOCKOUT_MAX_FAILURES; $i++)
    {
        $session = UserLogin::Login("lockout", "lockout");
    }
    UserLogin::LogOut($session); // Tags take care of removing the others
    $res = UserLockout::IsLockedOut("lockout");
    test_assert($res === FALSE, "Good login doesn't increment failure count");
    for($i = 0; $i < LOCKOUT_MAX_FAILURES; $i++)
    {
        UserLogin::Login("lockout", "wrong");
    }
    $res = UserLockout::IsLockedOut("lockout");
    test_assert($res === TRUE, "Locked out after LOCKOUT_MAX_FAILURES");
    $res = UserLogin::Login("lockout", "lockout", 30);
    test_assert($res === FALSE, "Can't log in when locked out");
    $res = Accounts::GetUserMasterKey("lockout", "lockout");
    test_assert($res === FALSE, "Can't get master key while locked out");
    $res = Accounts::ChangePassword("lockout", "lockout", "diff");
    test_assert($res === FALSE, "Can't change password when locked out");
    Accounts::DeleteAccount("lockout");

    // Make sure changepassword locks out as well
    Accounts::CreateAccount("lockout2", $bogusemail, "lockout2", TRUE);
    EmailValidation::SetUserValidatedByName("lockout2");
    $res = UserLockout::IsLockedOut("lockout2");
    test_assert($res === FALSE, "Not initially locked out");
    for($i = 0; $i < 2 * LOCKOUT_MAX_FAILURES; $i++)
    {
        $session = UserLogin::Login("lockout2", "lockout2");
    }
    UserLogin::LogOut($session); // Tags take care of removing the others
    $res = UserLockout::IsLockedOut("lockout2");
    test_assert($res === FALSE, "Good login doesn't increment failure count");
    for($i = 0; $i < LOCKOUT_MAX_FAILURES; $i++)
    {
        Accounts::ChangePassword("lockout2", "wrong", "lockout2");
    }
    $res = UserLockout::IsLockedOut("lockout2");
    test_assert($res === TRUE, "Locked out after LOCKOUT_MAX_FAILURES");
    Accounts::DeleteAccount("lockout2");

    test_allpass();
?>
