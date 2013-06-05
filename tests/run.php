<?php

exitIfNotInCommandLine();
if(realpath(__FILE__) != realpath("./tests/" . basename(__FILE__)) || !is_dir("./tests/tests"))
{
    echo "Please run this script from the root directory.\n";
    usage();
}

require_once("tests/Timer.php");
require_once("tests/Asserts.php");


$testList = getTestPathList();

foreach($testList as $path)
{
    require_once($path);
}

$date = getFormattedDate();
echo "==== RUNNING TESTS [$date] ====\n";
$success = TRUE;
$allTimer = new Timer();
foreach($testList as $test)
{
    $success = runTest($test) && $success;
}

$time = round($allTimer->stop(), 5);

if($success)
{
    echo "ALL TESTS PASSED! [{$time}s]\n";
}
else
{
    echo "SOME TESTS FAILED! [{$time}s]\n";
}

function runTest($testPath)
{
    $className = getClassName($testPath);
    if($className)
    {
        testClassStart($className);
        $testClassTimer = new Timer();
        $testObj = new $className();

        $allMethods = get_class_methods($className);
        $testMethods = getTestMethods($className);
        shuffle($testMethods);

        callIfExists($testObj, "initialSetup");

        $allSuccess = TRUE;
        foreach($testMethods as $test)
        {
            $thisSuccess = TRUE;
            callIfExists($testObj, "beginTest");
            $testTimer = new Timer();
            testStart($test);
            tassert_reset();
            $retVal = $testObj->$test();
            if($retVal !== null)
                $thisSuccess &= $retVal;
            $thisSuccess &= tassert_status();
            testEnd($test, $testTimer->stop(), $thisSuccess);
            callIfExists($testObj, "endTest");
            $allSuccess &= $thisSuccess;
        }

        callIfExists($testObj, "finalTeardown");

        testClassEnd($className, $testClassTimer->stop(), $allSuccess); 
        return $allSuccess;
    }
    else
    {
        echo "[ERROR] Can't find class in $testPath\n";
        return FALSE;
    }
}

function testClassStart($name)
{
    echo "\x1B[0;34m\x1B[1m$name:\x1B[0m\x1B[0m\n";
}

function testClassEnd($name, $seconds, $success)
{
    $seconds = round($seconds, 4);
    $res = ($success) ? "\x1B[0;32mALL PASS\x1B[0m" : "\x1B[0;31mFAIL\x1B[0m";
    echo "\t[$res] [{$seconds}s]\n\n";
}

function getFormattedDate()
{
    return date("F j, Y, g:i a");
}

function testStart($name)
{
    echo "\t$name " . str_repeat(".", 35 - strlen($name)). " ";
}

function testEnd($name, $seconds, $success)
{
    $seconds = round($seconds, 4);
    $res = ($success) ? "\x1B[0;32mPASS\x1B[0m" : "\x1B[0;31mFAIL\x1B[0m";
    echo "[$res] [{$seconds}s]\n"; 
}

function callIfExists($obj, $methodName)
{
    $methods = get_class_methods(get_class($obj));  
    if(in_array($methodName, $methods))
    {
        //echo "\t- $methodName\n";
        $obj->$methodName();
    }
}

function getTestMethods($className)
{
    $methods = get_class_methods($className);
    $testMethods = array();
    foreach($methods as $method)
    {
        if(strpos($method, "test") === 0)
            $testMethods[] = $method;
    }
    return $testMethods;
}

function getClassName($path)
{
    $contents = file_get_contents($path);
    preg_match("/^\s*class\s+(\S+)/m", $contents, $matches);
    if(count($matches) > 1)
        return $matches[1];
    else
        return FALSE;
}

function getTestPathList()
{
    global $argc, $argv;
    if($argc < 2)
        usage();
    if($argc == 2 && $argv[1] == "--all")
        return listAllTests();
    else
    {
        $list = array();
        for($i = 1; $i < $argc; $i++)
            $list[] = getFullTestPath($argv[$i]);
        return $list;
    }
}

function exitIfNotInCommandLine()
{
    if (PHP_SAPI != "cli") 
    {
        echo "This is a command line program.\n";
        usage();
    }
}

function usage()
{
    die("Usage: runtests.php [test1 [test2 [test3...]]]\n\truntests.php --all\n");
}

function getFullTestPath($name)
{
    $testDir = getTestDir();
    $name = str_replace(".", "/", $name);
    return $testDir . "/" . $name . ".php";
}

function listAllTests()
{
    $testDir = getTestDir();
    $list = array();
    addTestsRecursively($testDir, $list);
    return $list;
}

function addTestsRecursively($testDir, &$list)
{
    $dh = opendir($testDir);
    while(($subfile = readdir($dh)) !== FALSE)
    {
        if($subfile == "." || $subfile == "..")
            continue;

        $subpath = $testDir . "/" . $subfile;
        if(is_dir($subpath))
            addTestsRecursively($subpath, $list);
        else if(strpos($subfile, ".php") == strlen($subfile) - 4)
            $list[] = $subpath;
    }
    closedir($dh);
}

function getTestDir()
{
    return realpath(dirname(__FILE__)) . "/tests";
}

?>
