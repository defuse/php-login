<?php
class Timer
{
    private $startTime;
    private $result;

    public function __construct()
    {
        $this->startTime = microtime(true);
        $this->result = 0;
    }

    public function stop()
    {
        $this->result = microtime(true) - $this->startTime;
        return $this->result;
    }
}
?>
