<?php
    $root = "/var/www/devel/securelogin/trunk/";
    chdir($root);

    require_once("inc/session.php");

    Session::RemoveStaleSessions();
?>
