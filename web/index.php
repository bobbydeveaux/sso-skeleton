<?php

use Symfony\Component\HttpFoundation\Request;

$app = require_once __DIR__.'/../app/app.php';

if (true === isset($argv) && count($argv) > 0) {
    list($_, $method, $path) = $argv;
    $request = Request::create($path, $method);
    $app->run($request);
} else {
    $app->run();
}
