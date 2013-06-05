<?php
class Escape
{
    public static function html($s)
    {
        return htmlentities($s, ENT_QUOTES);
    }

    public static function JavaScriptStringLiteral($s)
    {
        // TODO: Check that this is good enough
        return addslashes(htmlentities($s, ENT_QUOTES));
    }

}
?>
