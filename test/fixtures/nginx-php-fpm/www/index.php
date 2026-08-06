<?php
// Fixture app for `catwaf auto` live testing. Plain and harmless — its only
// job is to prove PHP is actually executing behind nginx, so the discovery
// pipeline has something real to detect.
?>
<!doctype html>
<html lang="en">
<head><meta charset="utf-8"><title>FreshMart — CatWAF discovery fixture</title></head>
<body style="font-family:system-ui,sans-serif;max-width:40rem;margin:3rem auto;line-height:1.6">
  <h1>FreshMart</h1>
  <p>Fixture application for CatWAF automatic discovery testing.</p>
  <ul>
    <li>PHP version: <?= htmlspecialchars(PHP_VERSION, ENT_QUOTES, 'UTF-8') ?></li>
    <li>SAPI: <?= htmlspecialchars(PHP_SAPI, ENT_QUOTES, 'UTF-8') ?></li>
    <li>Server: <?= htmlspecialchars($_SERVER['SERVER_SOFTWARE'] ?? 'unknown', ENT_QUOTES, 'UTF-8') ?></li>
  </ul>
</body>
</html>
