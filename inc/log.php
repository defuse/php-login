<?php
require_once('inc/email.php');


//TODO: make the log numeric and have a MIN_EMAIL_LEVEL
//TODO: (optional) SYSLOG
//TODO: (optional) flat file logging

define("LOG_SEND_ALERT_EMAIL", TRUE);
define("LOG_ALERT_EMAIL", "firexware@gmail.com");
define("LOG_ALERT_EMAIL_SRC", "log@invalid.invalid");
define("LOG_APP_IDENT", "LOGINSYS");

define("LOG_LEVEL_CRITICAL", "CRITICAL");
define("LOG_LEVEL_WARNING", "WARNING");
define("LOG_LEVEL_NOTICE", "NOTICE");
define("LOG_LEVEL_DEFAULT", LOG_LEVEL_WARNING);

//TODO: Actually implement the logging functionality
class Log
{
    private function __construct() {}

    public static function LogError($message, $level = LOG_LEVEL_DEFAULT)
    {
        if(LOG_SEND_ALERT_EMAIL)
        {
            $today = date("F j, Y, g:i a");
            $backtrace = self::BacktraceToStr(debug_backtrace());
            $report = $level . ": " . LOG_APP_IDENT . "\n" .
                      "Message: $message\n\n" . $backtrace;
            Email::SendMail(LOG_ALERT_EMAIL_SRC, LOG_ALERT_EMAIL, "Error Log", $report, $report);
        }
    }

    private static function BacktraceToStr($backtrace)
    {
        $str = "---BEGIN BACKTRACE---\n";
        $backtrace = array_reverse($backtrace);
        $i = 1;
        foreach($backtrace as $call)
        {
            $file = isset($call['file']) ? $call['file'] : '';
            $line = isset($call['line']) ? $call['line'] : '';
            $class = isset($call['class']) ? $call['class'] : '';
            $type = isset($call['type']) ? $call['type'] : '';
            $function = isset($call['function']) ? $call['function'] : '';

            $str .= "[$i] {$file}:{$call['line']} {$class}{$type}{$function} \n";
            $i++;
        }
        $str .= "---END BACKTRACE---";
        return $str;
    }
}
?>
