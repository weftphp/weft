<?php
use Weft\{Channel, WaitGroup, Mutex};
use function Weft\{run, go, sleep, after, tick, clear};

run(function () {
    // Channel with several producers.
    $ch = new Channel(2);
    $wg = new WaitGroup();
    foreach ([1, 2, 3] as $i) {
        $wg->add();
        go(function () use ($ch, $wg, $i) {
            $ch->push(["worker" => $i, "obj" => new ArrayObject([$i])]);
            $wg->done();
        });
    }
    go(function () use ($ch, $wg) { $wg->wait(); $ch->close(); });
    $got = [];
    while (($v = $ch->pop()) !== null) $got[] = $v["worker"] . ":" . count($v["obj"]);
    sort($got);
    echo implode(" ", $got), "\n";
    var_dump($ch->isClosed(), $ch->push(1), $ch->pop(0.01));

    // Timeout on an empty channel.
    $empty = new Channel(1);
    var_dump($empty->pop(0.02), $empty->length(), $empty->capacity());

    // Mutex hands over in arrival order.
    $m = new Mutex(); $order = []; $wg = new WaitGroup();
    foreach ([1, 2, 3] as $i) {
        $wg->add();
        go(function () use ($m, $wg, $i, &$order) {
            $m->lock(); sleep(0.01); $order[] = $i; $m->unlock(); $wg->done();
        });
    }
    $wg->wait();
    echo implode(",", $order), "\n";
    var_dump($m->tryLock(), $m->tryLock(), $m->isLocked());
    $m->unlock();
    try { $m->unlock(); } catch (Weft\Exception $e) { echo $e->getMessage(), "\n"; }

    // WaitGroup wait with timeout.
    $w = new WaitGroup(); $w->add(); var_dump($w->count(), $w->wait(0.02));

    // Timers.
    $n = 0;
    $t = tick(0.01, function () use (&$n) { $n++; });
    after(0.055, function () use ($t) { echo "after fired\n"; clear($t); });
    sleep(0.1);
    var_dump($n >= 4 && $n <= 6, clear($t));
    // A tick left running does not keep run() alive.
    tick(1, function () {});
});
echo "done\n";
