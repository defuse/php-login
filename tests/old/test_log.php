<?php
require_once('tests/old/testlib.php');
require_once('inc/email.php');
require_once('inc/log.php');

unlink(EMAIL_DEBUG_FILE);
Log::LogError("Testing Log", LOG_NOTICE);
$str = file_get_contents(EMAIL_DEBUG_FILE);
test_assert(strlen($str) > 10, "Log sends email.");

?>
