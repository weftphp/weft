<?php
use function Weft\{run, go, sleep, cid, count, suspend, resume, exists, pass};

function depth(int $n): int { return $n === 0 ? 0 : 1 + depth($n - 1); }

$sum = 0;
run(function () use (&$sum) {
    echo "main cid=", cid(), "\n";

    // Coroutines interleave by their sleeps.
    foreach ([3, 1, 2] as $n) {
        go(function (int $n) { sleep(0.02 * $n); echo "woke $n\n"; }, $n);
    }
    sleep(0.1);

    // Switching inside a callback called by an internal function.
    echo implode(",", array_map(function ($x) { sleep(0.001); return $x * 2; }, [1, 2, 3])), "\n";

    // try/catch across a switch.
    go(function () {
        try { sleep(0.01); throw new Exception("boom"); }
        catch (Exception $e) { echo "caught ", $e->getMessage(), "\n"; }
    });
    sleep(0.05);

    // Deep PHP recursion on a coroutine stack.
    echo depth(20000), "\n";

    // suspend / resume / pass / exists.
    $log = [];
    $id = go(function () use (&$log) { $log[] = "a"; suspend(); $log[] = "b"; });
    pass();
    var_dump(exists($id));
    resume($id);
    var_dump(exists($id));
    echo implode("", $log), "\n";

    // Many coroutines.
    for ($i = 0; $i < 5000; $i++) {
        go(function () use (&$sum) { sleep(0.01); $sum++; });
    }
    sleep(0.2);
    echo "live: ", count(), "\n";
});
echo "sum=$sum\n";

// An exception escaping a coroutine is rethrown by run().
try {
    run(function () { go(function () { throw new RuntimeException("escaped"); }); sleep(0.01); });
} catch (Throwable $e) {
    echo get_class($e), ": ", $e->getMessage(), "\n";
}

// Misuse is reported as Weft\Exception.
try { go(fn() => 1); } catch (Weft\Exception $e) { echo $e->getMessage(), "\n"; }
try { run(function () { run(fn() => 1); }); } catch (Weft\Exception $e) { echo $e->getMessage(), "\n"; }
echo "end\n";
