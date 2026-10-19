<?php
use function Weft\{run, go, sleep};
use function Weft\Http\request;

// Starts a server in a child PHP process, queries it, and stops it.
$port = 20000 + getmypid() % 20000;
$server = <<<'PHP'
use Weft\Http\{Server, Request, Response};
use function Weft\{sleep, go};
$server = new Server("127.0.0.1", (int) $argv[1], ["workers" => 2]);
$server->handle(function (Request $req, Response $res) {
    switch ($req->path()) {
        case "/slow": sleep(0.2); $res->header("X-Slow", "1")->end("slow"); break;
        case "/boom": throw new Exception("handler failed");
        case "/echo":
            $res->header("Content-Type", "application/json")->end(json_encode([
                "method" => $req->method(), "query" => $req->query(), "body" => $req->body(),
                "header" => $req->header("x-test"), "cookies" => $req->cookies(),
            ]));
            break;
        case "/later": go(function () use ($res) { sleep(0.05); $res->status(202)->end("from another coroutine"); }); break;
        default: $res->status(404)->end("not found");
    }
});
$server->start();
PHP;
$proc = proc_open(
    [PHP_BINARY, "-n", "-d", "extension=" . getenv("WEFT_EXT"), "-d", "display_errors=0", "-r", $server, "--", (string) $port],
    [0 => ["file", "/dev/null", "r"], 1 => ["file", "/dev/null", "w"], 2 => ["file", "/dev/null", "w"]],
    $pipes
);
register_shutdown_function(function () use ($proc) {
    $status = proc_get_status($proc);
    if ($status["running"]) { posix_kill($status["pid"], SIGTERM); }
    proc_close($proc);
});

run(function () use ($port) {
    $base = "http://127.0.0.1:$port";
    for ($i = 0; $i < 100; $i++) {
        try { request("GET", "$base/echo"); break; } catch (Weft\Exception $e) { sleep(0.05); }
    }

    $r = request("POST", "$base/echo?a=1&b=two", ["X-Test" => "yes", "Cookie" => "k=v"], "hello");
    echo $r["status"], " ", $r["headers"]["content-type"], " ", $r["body"], "\n";

    $r = request("GET", "$base/missing");
    echo $r["status"], " ", $r["body"], "\n";

    $r = request("GET", "$base/boom");
    echo $r["status"], "\n";

    $r = request("GET", "$base/later");
    echo $r["status"], " ", $r["body"], "\n";

    // Slow handlers overlap: six 0.2s requests finish in well under their 1.2s sum.
    $t = microtime(true); $ok = 0; $wg = new Weft\WaitGroup();
    for ($i = 0; $i < 6; $i++) {
        $wg->add();
        go(function () use (&$ok, $wg, $base) {
            $r = request("GET", "$base/slow");
            if ($r["status"] === 200 && $r["headers"]["x-slow"] === "1") $ok++;
            $wg->done();
        });
    }
    $wg->wait();
    echo "slow ok=$ok overlapped=", var_export(microtime(true) - $t < 0.8, true), "\n";
});
