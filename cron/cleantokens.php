<?php
    $root = "/var/www/devel/securelogin/trunk/";
    chdir($root);

    require_once('inc/EmailValidation.php');
    require_once('inc/UserLockout.php');
    require_once('inc/PasswordReset.php');

    EmailValidation::RemoveStaleTokens();
    UserLockout::RemoveStaleTokens();
    PasswordReset::RemoveStaleTokens();
?>
