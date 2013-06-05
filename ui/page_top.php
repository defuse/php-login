<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Transitional//EN" "http://www.w3.org/TR/xhtml1/DTD/xhtml1-transitional.dtd">
<html xmlns="http://www.w3.org/1999/xhtml" >
<head>
<title>Defuse Cyber-Security's Secure User Account System for PHP</title>
<meta name="keywords" content="defuse, login system, user account, security, encryption, login" />
<meta http-equiv="Content-Type" content="text/html; charset=utf-8" />
<link rel="stylesheet" media="all" type="text/css" href="style.css" />
</head>
<body>
<div id="header">
    <h1><a href="https://defuse.ca/">Defuse Cyber-Security's</a> Secure User Account System for PHP</h1>
</div>
<div id="navbar">
    <?php
        if(isset($USER))
        {
        ?>
            <a href="profile.php">Your Notepad</a> | 
            <a href="settings.php">Account Settings</a> |
            <a href="logout.php">Logout</a>
        <?
        }
        else
        {
        ?>
            <a href="index.php">Home</a>  
        <?
        }
    ?>
</div>
<div id="content">
