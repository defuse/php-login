<?php
error_reporting(E_ALL | E_STRICT | E_NOTICE | E_DEPRECATED | E_USER_DEPRECATED | E_RECOVERABLE_ERROR);
set_error_handler('handler', E_ALL | E_STRICT | E_NOTICE | E_DEPRECATED | E_USER_DEPRECATED | E_RECOVERABLE_ERROR);

$ASSERT_SUCCESS = TRUE;

function tassert_eq($expected, $actual, $msg = "")
{
    return tassert($expected == $actual, $msg);
}

function tassert_eqs($expected, $actual, $msg = "")
{
    return tassert($expected === $actual, $msg);
}

function tassert($bool, $msg = "")
{
    global $ASSERT_SUCCESS;
    if(!$bool)
    {
        echo "\t\t[ASSERT FAIL] $msg\n";
        $ASSERT_SUCCESS = FALSE;
        return FALSE;
    }
    else
        return TRUE;
}

function tassert_reset()
{
    global $ASSERT_SUCCESS;
    $ASSERT_SUCCESS = TRUE;
}

function tassert_status()
{
    global $ASSERT_SUCCESS; 
    return $ASSERT_SUCCESS;
}

function handler($errno, $errmsg, $filename, $linenum, $vars)
{
    global $ASSERT_SUCCESS;
    $ASSERT_SUCCESS = FALSE;
    echo "\t\t[ERROR] - $filename:$linenum\n";
    echo "\t\t\t$errmsg\n";
    echo "\t\t\tBacktrace:\n";
    printBacktrace(debug_backtrace());
}

function printBacktrace($backtrace)
{
    for($i = count($backtrace) - 1; $i >= 0; $i--)
    {
        $frame = $backtrace[$i];
        if(!isset($frame['class']))
            $frame['class'] = '';
        if(!isset($frame['type']))
            $frame['type'] = '';
        if(!isset($frame['file']))
            $frame['file'] = '';
        if(!isset($frame['line']))
            $frame['line'] = '';
        echo "\t\t\t    {$frame['class']}{$frame['type']}{$frame['function']}(), " .
                      "{$frame['file']}:{$frame['line']}\n";
    }
}

?>
