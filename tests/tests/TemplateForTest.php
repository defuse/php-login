<?php
class TemplateForTest
{
    // Executes once before any tests
    function initialSetup()
    {

    }

    // Executes once after all tests have finished
    function finalTeardown()
    {

    }

    // Executes before every test
    function beginTest()
    {

    }

    // Executes after every test
    function endTest()
    {

    }

    // Functions starting with "test" are executed in a random order
    // Function return value determines pass or fail

    function testOnePlusOne()
    {
        $result = 1 + 1; 
        tassert_eqs(2, $result, "1+1=2");
    }

    function testTwoPlusTwo()
    {
        $result = 2 + 2;
        tassert_eqs(4, $result, "2+2=4");
    }

}
?>
