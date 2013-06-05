<?php

require_once('inc/security.conf.php');

class Filter 
{
    private function __construct() {}

    public static function IsValidUsername($username)
    {
        if(strlen($username) > MAX_USERNAME_LENGTH)
            return FALSE;

        return self::ContainsOnly($username, SAFE_USERNAME_CHARACTERS);
    }

    public static function IsValidEmail($email)
    {
        //TODO: Check format like name@example.com
        if(strlen($email) > MAX_EMAIL_LENGTH)
            return FALSE;
        
        return self::ContainsOnly($email, SAFE_EMAIL_CHARACTERS);
    }

    public static function ConformsToPasswordPolicy($password)
    {
        if(strlen($password) > PASSWORDPOLICY_MAXLENGTH || strlen($password) < PASSWORDPOLICY_MINLENGTH)
            return false;
        if(PASSWORDPOLICY_REQUIRE_DIGIT && !self::ContainsAny($password, "0123456789"))
            return false;
        if(PASSWORDPOLICY_REQUIRE_SYMBOL && !self::ContainsAny($password, "~`!@#$%^&*()_+-={[}]|\\:;\"'<,>.?/"))
            return false;
        if(PASSWORDPOLICY_REQUIRE_UPPERALPHA && !self::ContainsAny($password, "ABCDEFGHIJKLMNOPQRSTUVWXYZ"))
            return false;
        if(PASSWORDPOLICY_REQUIRE_LOWERALPHA && !self::ContainsAny($password, "abcdefghijklmnopqrstuvwxyz"))
            return false;
        return true;
    }

    private static function ContainsOnly($string, $only)
    {
        for($i = 0; $i < strlen($string); $i++)
        {
            if(strpos($only, substr($string, $i, 1)) === FALSE)
            {
                return FALSE;
            }
        }
        return TRUE;
    }

    private static function ContainsAny($password, $symbols)
    {
        $found = false;
        for($i = 0; $i < strlen($symbols); $i++)
        {
            if(strpos($password, substr($symbols, $i, 1)) !== false)
                $found = true;
        }
        return $found;
    }
}

?>
