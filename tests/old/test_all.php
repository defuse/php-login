<?php
require_once('tests/old/testlib.php');

// Simply run all of the tests
if(!is_dir("./tests/old"))
{
    echo "Please run this script from the directory containing the 'tests' subdirectory.\n";
    die();
}

$dir = opendir("./tests/old");

if(!$dir)
{
    echo "Couldn't list directory... for some reason...\n";
}

$list = array();

while(($file = readdir($dir)) !== FALSE)
{
    $file = basename($file);
    // Everything starting with test_ is a test
    if($file != "test_all.php" && strpos($file, "test_") === 0)
    {
        echo "#####################################################################\n";
        echo "$file\n";
        echo "#####################################################################\n";
        $list[] = $file;
        include("./tests/old/$file");
    }
}

$cnt = count($list);
echo "\n\nFinished $cnt test groups...\n";
foreach($list as $file)
{
    echo " o $file\n";
}
test_allpass();
?>
