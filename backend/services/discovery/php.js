// discovery/php.js — multi-signal PHP + framework detection.
//
// No single signal is trusted on its own (an image tagged `*-php` might not
// even be running PHP; a stray `index.php` might be a leftover file). Every
// signal below contributes points to a confidence score; only the combined
// total decides the verdict.
//
// ── Scoring model ─────────────────────────────────────────────────────
//   Docker image name contains php/wordpress/drupal/joomla/...   +40
//   php-fpm process running (docker top)                         +40
//   FastCGI wired to a PHP-FPM container (config-confirmed)       +45
//   FastCGI backend inferred from network topology alone          +25
//   FastCGI to a local unix socket / loopback                     +30
//   bare `php` process running (cli / built-in server)            +25
//   nginx or apache detected as the front webserver                +10
//   index.php present in a common webroot                         +15
//   composer.json present                                         +10
//   vendor/ directory present                                      +5
//   HTTP response header `X-Powered-By: PHP...`                   +10
//   HTTP response body contains PHP/framework fingerprints        up to +10
//
// The FastCGI signals are what let a split nginx + PHP-FPM deployment be
// recognized: the nginx container has no PHP on it at all, so without them
// it scores 10 (webserver only) and is correctly classified as static.
// Config-confirmed wiring alone (+45) clears the "likely" threshold; a
// topology-only inference (+25) needs the +10 webserver signal and one more
// corroborating signal before it will, which is intentional.
//
// Framework-specific filesystem signals additionally set `framework`:
//   Laravel `artisan` file                                        +15
//   WordPress `wp-config.php`                                     +20
//   Drupal `sites/default/settings.php`                            +15
//
// ── Thresholds ────────────────────────────────────────────────────────
//   confidence >= 70   "PHP" — high confidence, safe to apply PHP-specific
//                       CRS exclusions (matches state.WAF.php_exclusions).
//   confidence 40–69   "PHP" — likely, reported with a lower confidence so
//                       the user can sanity-check it.
//   confidence <  40   not classified as PHP.
//
// These thresholds are intentionally conservative: false positives cause
// CatWAF to loosen CRS rules (php_exclusions) it shouldn't, so 40 is a
// floor, not a suggestion.

const PHP_IMAGE_RE = /(^|[/:-])(php|wordpress|drupal|joomla|magento|prestashop|laravel|craftcms)([/:.-]|$)/i
const WEBROOTS = ['/var/www/html', '/app', '/srv/app', '/var/www', '/usr/share/nginx/html', '/srv/www']
const PROBE_FILES = ['index.php', 'composer.json', 'vendor', 'artisan', 'wp-config.php', 'sites/default/settings.php']

const HIGH_CONFIDENCE = 70
const LIKELY_CONFIDENCE = 40

// Webroots that reach this module come from a CONTAINER'S OWN CONFIG FILE
// (Apache DocumentRoot / nginx root), which is untrusted input, and they are
// interpolated into a `sh -c` command run via `docker exec`. Command
// substitution expands inside double quotes, so a DocumentRoot of
// /var/www/`id` would execute `id` in that container. Only plain absolute
// paths are ever interpolated.
const SAFE_PATH_RE = /^\/[A-Za-z0-9._\-/]*$/
const MAX_EXTRA_WEBROOTS = 8

function safeWebroots(paths) {
  const out = []
  for (const p of Array.isArray(paths) ? paths : []) {
    if (typeof p !== 'string') continue
    if (p.length > 512) continue
    if (!SAFE_PATH_RE.test(p)) continue
    if (p.includes('..')) continue
    out.push(p.replace(/\/+$/, '') || '/')
    if (out.length >= MAX_EXTRA_WEBROOTS) break
  }
  return out
}

function buildProbeScript(extraWebroots = []) {
  const lines = []
  // DocumentRoot from the server's own config first — a webroot the config
  // actually names beats the conventional guesses.
  const roots = [...new Set([...safeWebroots(extraWebroots), ...WEBROOTS])]
  for (const dir of roots) {
    for (const f of PROBE_FILES) {
      lines.push(`[ -e "${dir}/${f}" ] && echo "${f}:${dir}"`)
    }
  }
  return lines.join('; ')
}

function probeFilesystem(dockerClient, container, extraWebroots = []) {
  if (!container.id || !container.running) return { ok: false, hits: [] }
  const result = dockerClient.execCapture(container.id, buildProbeScript(extraWebroots))
  if (!result.ok) return { ok: false, hits: [] }
  const hits = result.stdout.split('\n').map(l => l.trim()).filter(Boolean).map(l => l.split(':')[0])
  return { ok: true, hits: [...new Set(hits)] }
}

function detectFromProcesses(processes) {
  if (!processes) return { phpFpm: false, phpCli: false }
  const joined = processes.join('\n').toLowerCase()
  return {
    phpFpm: /php-fpm/.test(joined),
    phpCli: !/php-fpm/.test(joined) && /\bphp\b/.test(joined),
  }
}

function extractPhpVersion(text) {
  const m = /PHP\/(\d+\.\d+(?:\.\d+)?)/i.exec(text || '')
  return m ? m[1] : null
}

const FASTCGI_POINTS = { config: 45, local: 30, 'network-inference': 25 }

// `container` is a normalized container (see containers.js), `webInfo` is
// the result of web.detectWebPort(), `processes` is dockerClient.topProcesses()
// output (or null if unavailable), `serverInfo` is discovery/runtime.js's
// webserver verdict for this container (used only for the +10 context bonus),
// and `fastcgi` is discovery/fastcgi.js's correlation result linking this
// container to a separate PHP-FPM backend (or null when there is none).
function detect(container, { dockerClient, webInfo, processes, serverInfo, fastcgi, extraWebroots = [] } = {}) {
  let score = 0
  const evidence = []
  let framework = null
  let phpVersion = null

  if (PHP_IMAGE_RE.test(container.image)) {
    score += 40
    evidence.push({ signal: 'docker-image', detail: `image "${container.image}" matches PHP/CMS pattern`, points: 40 })
  }

  const { phpFpm, phpCli } = detectFromProcesses(processes)
  if (phpFpm) {
    score += 40
    evidence.push({ signal: 'process', detail: 'php-fpm process running', points: 40 })
  } else if (phpCli) {
    score += 25
    evidence.push({ signal: 'process', detail: 'php process running', points: 25 })
  }

  if (fastcgi && FASTCGI_POINTS[fastcgi.basis]) {
    const points = FASTCGI_POINTS[fastcgi.basis]
    score += points
    evidence.push({
      signal: 'fastcgi',
      detail: fastcgi.detail || (fastcgi.basis === 'local'
        ? `FastCGI handled locally (${fastcgi.target})`
        : `FastCGI backend ${fastcgi.target}`),
      points,
    })
    if (fastcgi.phpVersion) phpVersion = fastcgi.phpVersion
  }

  if (serverInfo && (serverInfo.server === 'nginx' || serverInfo.server === 'apache')) {
    score += 10
    evidence.push({ signal: 'webserver', detail: `fronted by ${serverInfo.server}`, points: 10 })
  }

  const envKeys = Object.keys(container.env || {})
  if (envKeys.some(k => /^WORDPRESS_/.test(k))) {
    score += 10
    framework = framework || 'WordPress'
    evidence.push({ signal: 'env', detail: 'WORDPRESS_* environment variables present', points: 10 })
  }
  // Env vars are attacker-controlled and this value ends up in generated
  // configuration, so only a bare version number is ever accepted.
  const envVersion = /^(\d+\.\d+(?:\.\d+)?)/.exec(String(container.env?.PHP_VERSION || ''))
  if (envVersion) {
    score += 5
    phpVersion = phpVersion || envVersion[1]
    evidence.push({ signal: 'env', detail: `PHP_VERSION=${envVersion[1]}`, points: 5 })
  }

  const fsProbe = probeFilesystem(dockerClient, container, extraWebroots)
  if (fsProbe.hits.includes('index.php')) {
    score += 15
    evidence.push({ signal: 'filesystem', detail: 'index.php found in webroot', points: 15 })
  }
  if (fsProbe.hits.includes('composer.json')) {
    score += 10
    evidence.push({ signal: 'filesystem', detail: 'composer.json found', points: 10 })
  }
  if (fsProbe.hits.includes('vendor')) {
    score += 5
    evidence.push({ signal: 'filesystem', detail: 'vendor/ directory found', points: 5 })
  }
  if (fsProbe.hits.includes('artisan')) {
    score += 15
    framework = 'Laravel'
    evidence.push({ signal: 'filesystem', detail: 'Laravel artisan file found', points: 15 })
  }
  if (fsProbe.hits.includes('wp-config.php')) {
    score += 20
    framework = 'WordPress'
    evidence.push({ signal: 'filesystem', detail: 'wp-config.php found', points: 20 })
  }
  if (!framework && fsProbe.hits.includes('sites/default/settings.php')) {
    score += 15
    framework = 'Drupal'
    evidence.push({ signal: 'filesystem', detail: 'Drupal sites/default/settings.php found', points: 15 })
  }

  const headers = webInfo?.httpCheck?.headers || {}
  const poweredBy = headers['x-powered-by'] || ''
  if (/php/i.test(poweredBy)) {
    score += 10
    evidence.push({ signal: 'http-header', detail: `X-Powered-By: ${poweredBy}`, points: 10 })
    phpVersion = extractPhpVersion(poweredBy) || phpVersion
  }

  const body = webInfo?.httpCheck?.bodySample || ''
  if (/wp-content|wp-includes/i.test(body)) {
    score += 10
    if (!framework) framework = 'WordPress'
    evidence.push({ signal: 'http-body', detail: 'WordPress asset paths in response body', points: 10 })
  } else if (/laravel_session|csrf-token/i.test(body)) {
    score += 10
    if (!framework) framework = 'Laravel'
    evidence.push({ signal: 'http-body', detail: 'Laravel fingerprints in response body', points: 10 })
  }

  if (!phpVersion) {
    const imgVersion = /php:?(\d+\.\d+)/i.exec(container.image)
    if (imgVersion) phpVersion = imgVersion[1]
  }

  const confidence = Math.max(0, Math.min(100, score))
  const isPhp = confidence >= LIKELY_CONFIDENCE

  return {
    isPhp,
    confidence,
    confidenceLabel: confidence >= HIGH_CONFIDENCE ? 'high' : (isPhp ? 'likely' : 'none'),
    framework,
    runtime: isPhp ? `PHP${phpVersion ? ' ' + phpVersion : ''}` : null,
    evidence,
  }
}

module.exports = { detect, PHP_IMAGE_RE, HIGH_CONFIDENCE, LIKELY_CONFIDENCE, buildProbeScript, safeWebroots }
