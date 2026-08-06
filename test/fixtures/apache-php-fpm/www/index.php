<?php
// ============================================================
//   CATWAF SECURITY TEST ENVIRONMENT
//
//        INTENTIONALLY VULNERABLE
//          LOCAL TESTING ONLY
// ============================================================
//
// This page reflects query input WITHOUT escaping, on purpose. Its whole
// job is to prove that CatWAF/Coraza refuses an attack payload BEFORE the
// application ever sees it — if a payload reaches this file, the WAF is
// not doing its job, and the reflection makes that visible.
//
// Same convention as docker/TestApp.Dockerfile: the compose file gives this
// service NO published ports, so it is reachable only from inside the
// fixture network, via Apache and then only through CatWAF.
//
// Do not publish this container. Do not deploy it anywhere reachable.

$q = $_GET['q'] ?? '';
$id = $_GET['id'] ?? '';
?>
<!doctype html>
<html lang="en">
<head><meta charset="utf-8"><title>BookNook — CatWAF Apache fixture</title></head>
<body style="font-family:system-ui,sans-serif;max-width:44rem;margin:3rem auto;line-height:1.6">
<pre style="background:#300;color:#fbb;padding:1rem;border-radius:8px">CATWAF SECURITY TEST ENVIRONMENT
INTENTIONALLY VULNERABLE — LOCAL TESTING ONLY</pre>

  <h1>BookNook</h1>
  <p>Apache + PHP-FPM fixture for CatWAF automatic discovery testing.</p>

  <ul>
    <li>PHP version: <?= htmlspecialchars(PHP_VERSION, ENT_QUOTES, 'UTF-8') ?></li>
    <li>SAPI: <?= htmlspecialchars(PHP_SAPI, ENT_QUOTES, 'UTF-8') ?></li>
    <li>Server: <?= htmlspecialchars($_SERVER['SERVER_SOFTWARE'] ?? 'unknown', ENT_QUOTES, 'UTF-8') ?></li>
  </ul>

  <!-- Deliberately unescaped: if this renders an injected payload, the WAF failed. -->
  <p>Search results for: <?= $q ?></p>
  <p>Looking up record: <?= $id ?></p>
</body>
</html>
