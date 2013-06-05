<?php
require_once('tests/old/testlib.php');
require_once('inc/session.php');

define("CREATE_SESSION_NUM", 10000);

$sessions = array();
timer_start('create_many_sessions');
for($i = 0; $i < CREATE_SESSION_NUM; $i++)
{
    $sessions[] = Session::BeginSession();
}
$t = timer_end();
$avg = $t / CREATE_SESSION_NUM;
info("Average create: $avg");


timer_start('delete_many_sessions');
foreach($sessions as $s)
{
    Session::EndSession($s);
}
$t = timer_end();
$avg = $t / CREATE_SESSION_NUM;
info("Average delete: $avg");

// Test how well it performs with a full session table
$sessions = array();
for($i = 0; $i < CREATE_SESSION_NUM; $i++)
{
    $sessions[] = Session::BeginSession();
}

timer_start('lots_of_sessions');
for($i = 0; $i < CREATE_SESSION_NUM; $i++)
{
    $s = Session::BeginSession();
    Session::EndSession($s);
}
timer_end();

foreach($sessions as $s)
{
    Session::EndSession($s);
}

//TODO: Test many attributes, w/ lots of diff attrs in db

$sessions = 0; // Free memory

$s = Session::BeginSession();
timer_start('create_values');
for($i = 0; $i < 10000; $i++)
{
    Session::SetValue($s, mt_rand() . mt_rand(), mt_rand());
}
timer_end();
Session::EndSession($s);
?>
