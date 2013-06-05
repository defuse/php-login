<?php
require_once('inc/email.php');
require_once('inc/log.php');

class TestLog
{
    function testLogEmail()
    {
        if(file_exists(EMAIL_DEBUG_FILE))
            unlink(EMAIL_DEBUG_FILE);
        Log::LogError("Testing Log", LOG_NOTICE);
        $str = file_get_contents(EMAIL_DEBUG_FILE);
        tassert(strlen($str) > 10, "Log sends email.");
    }
}
?>
