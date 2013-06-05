<?php
/*
 * This code is hereby placed into the public domain by its author Taylor 
 * Hornby. It may be freely used for any purpose whatsoever.
 *
 * Developer's Contact Information:
 * WWW:     https://defuse.ca/
 * EMAIL:   <fillmein>
 * 
 * ***DISCLAIMER***
 *
 * ALL PUBLIC DOMAIN MATERIAL IS OFFERED AS-IS. NO REPRESENTATIONS OR
 * WARRANTIES OF ANY KIND ARE MADE CONCERNING THE MATERIALS, EXPRESS,
 * IMPLIED, STATUTORY OR OTHERWISE, INCLUDING, WITHOUT LIMITATION,
 * WARRANTIES OF TITLE, MERCHANTIBILITY, FITNESS FOR A PARTICULAR PURPOSE,
 * NONINFRINGEMENT, OR THE ABSENCE OF LATENT OR OTHER DEFECTS, ACCURACY, OR
 * THE PRESENCE OF ABSENCE OF ERRORS, WHETHER OR NOT DISCOVERABLE.
 * 
 * Limitation on Liability.
 * 
 * IN NO EVENT WILL THE AUTHOR(S), PUBLISHER(S), OR PRESENTER(S) OF ANY
 * PUBLIC DOMAIN MATERIAL BE LIABLE TO YOU ON ANY LEGAL THEORY FOR ANY
 * SPECIAL, INCIDENTAL, CONSEQUENTIAL, PUNITIVE OR EXEMPLARY DAMAGES
 * ARISING OUT OF THIS LICENSE OR THE USE OF THE WORK, EVEN IF THE
 * AUTHOR(S), PUBLISHER(S), OR PRESENTER(S) HAVE BEEN ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGES.
*/
    if(!isset($allgood))
        $allgood = true;

    $last_timer = FALSE;
    $timer = array();

    function timer_start($name)
    {
        global $last_timer, $timer;
        info("TIMER START: $name");
        $timer[$name] = microtime(TRUE);
        $last_timer = $name;
    }

    function timer_end($name = FALSE)
    {
        $now = microtime(TRUE);
        global $last_timer, $timer;

        if($name === FALSE)
            $name = $last_timer;

        if(!isset($timer[$name]))
        {
            echo "[ERROR] Timer $name not set!\n";
            return;
        }

        $then = $timer[$name];
        $time = $now - $then;
        $stime = number_format($time, 6);

        echo "[TIMER: $name] $stime\n";
        unset($timer[$name]);
        return $time;
    }

    function test_assert($bool, $msg)
    {
        global $allgood;
        $allgood = $allgood && $bool;

        if($bool)
            echo "[PASS]: ";
        else
            echo "[FAIL]: ";

        echo $msg . "\n";
    }

    function test_assert_equal($a, $b, $msg)
    {
        global $allgood;

        echo "[TESTING] $a == $b\n";
        $bool = $a == $b;
        $allgood = $allgood && $bool;
        test_assert($bool, $msg);
    }

    function test_refute_equal_strong($a, $b, $msg)
    {
        global $allgood;

        $bool = $a !== $b;
        $allgood = $allgood && $bool;
        test_assert($bool, $msg);
    }

    function test_assert_equal_strong($a, $b, $msg)
    {
        global $allgood;

        $bool = $a === $b;
        $allgood = $allgood && $bool;
        test_assert($bool, $msg);
    }

    function test_allpass()
    {
        global $allgood;
        if($allgood)
            echo ">>ALL TESTS PASS!<<\n";
        else
            echo ">>FAIL!<<\n";
    }


    function info($msg)
    {
        echo "[INFO] $msg\n";
    }
?>
