<?php
use Weft\{Socket, WaitGroup};
use function Weft\{run, go};
use function Weft\Http\request;

run(function () {
    $srv = Socket::listen("127.0.0.1", 0, 64);
    $port = (int) substr(strrchr($srv->local(), ":"), 1);
    go(function () use ($srv) {
        // close() wakes a pending accept() with an exception, which ends this loop.
        while (true) {
            try { $c = $srv->accept(1.0); } catch (Weft\Exception $e) { echo "accept stopped\n"; return; }
            if ($c === null) return;
            go(function () use ($c) {
                $data = $c->recv();
                if (str_starts_with($data, "GET /")) {
                    $c->send("HTTP/1.1 200 OK\r\nContent-Length: 5\r\nX-A: b\r\nConnection: close\r\n\r\nhello");
                } else {
                    while ($data !== "" && $data !== null) { $c->send(strtoupper($data)); $data = $c->recv(); }
                }
                $c->close();
            });
        }
    });

    $c = Socket::connect("127.0.0.1", $port, 2.0);
    $c->send("ping"); echo $c->recv(), "\n";
    $c->send("pong"); echo $c->recv(), "\n";
    $c->close();
    var_dump($c->isClosed());
    try { $c->send("x"); } catch (Weft\Exception $e) { echo $e->getMessage(), "\n"; }

    $r = request("GET", "http://127.0.0.1:$port/", ["X-Foo" => "bar"]);
    echo $r["status"], " ", $r["reason"], " ", $r["body"], " ", $r["headers"]["x-a"], "\n";

    try { Socket::connect("127.0.0.1", 1, 1.0); } catch (Weft\Exception $e) { echo "refused\n"; }

    $ok = 0; $wg = new WaitGroup();
    for ($i = 0; $i < 60; $i++) {
        $wg->add();
        go(function () use (&$ok, $wg, $i, $port) {
            $c = Socket::connect("127.0.0.1", $port, 5.0);
            $c->send("m$i");
            if ($c->recv() === "M$i") $ok++;
            $c->close();
            $wg->done();
        });
    }
    $wg->wait();
    echo "echoed $ok/60\n";
    $srv->close();
});
echo "end\n";
