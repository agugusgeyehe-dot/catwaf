#!/usr/bin/env node
// test/discovery.test.js — `catwaf auto` discovery + proxy generation.
//
// Docker is mocked throughout: a fake client implementing the same
// interface as discovery/docker.js's createDockerClient() is injected into
// discovery.discover({ dockerClient }), so none of this needs a real Docker
// daemon or a running Caddy.

const fs = require('fs')
const os = require('os')
const path = require('path')
const http = require('http')
const { execFileSync } = require('child_process')

const ROOT = path.join(__dirname, '..')
const WORK = fs.mkdtempSync(path.join(os.tmpdir(), 'catwaf-discovery-'))

process.env.DB_DIR = path.join(WORK, 'db')
process.env.CADDYFILE_PATH = path.join(WORK, 'Caddyfile')
process.env.CORAZA_AUDIT_LOG = path.join(WORK, 'logs', 'audit.json')
process.env.JWT_SECRET = 't'.repeat(64)
// Never let a reload reach a Caddy the developer is running locally:
// `caddy reload` targets CADDY_ADMIN_URL, which defaults to :2019.
process.env.CADDY_ADMIN_URL = 'http://127.0.0.1:19919'

fs.mkdirSync(process.env.DB_DIR, { recursive: true })
fs.mkdirSync(path.join(WORK, 'logs'), { recursive: true })

const BASE_CADDYFILE = [
  '{',
  '    order coraza_waf first',
  '}',
  '',
  ':9990 {',
  '    respond "upstream" 200',
  '}',
  '',
].join('\n')
fs.writeFileSync(process.env.CADDYFILE_PATH, BASE_CADDYFILE)

let pass = 0, fail = 0
function check(name, cond, extra) {
  if (cond) { pass++; console.log('  ok   ' + name) }
  else { fail++; console.log('  FAIL ' + name, extra !== undefined ? JSON.stringify(extra) : '') }
}
function section(t) { console.log('\n== ' + t + ' ==') }
process.on('exit', () => { try { fs.rmSync(WORK, { recursive: true, force: true }) } catch {} })

const discovery = require(path.join(ROOT, 'backend/services/discovery/index.js'))
const phpSvc = require(path.join(ROOT, 'backend/services/discovery/php.js'))
const containersSvc = require(path.join(ROOT, 'backend/services/discovery/containers.js'))
const fastcgiSvc = require(path.join(ROOT, 'backend/services/discovery/fastcgi.js'))
const webserversSvc = require(path.join(ROOT, 'backend/services/discovery/webservers.js'))
const routesSvc = require(path.join(ROOT, 'backend/services/proxy/routes.js'))
const generatorSvc = require(path.join(ROOT, 'backend/services/proxy/generator.js'))
const applySvc = require(path.join(ROOT, 'backend/services/proxy/apply.js'))
const networkSvc = require(path.join(ROOT, 'backend/services/proxy/network.js'))
const verifySvc = require(path.join(ROOT, 'backend/services/proxy/verify.js'))
const configTx = require(path.join(ROOT, 'backend/services/configTx.js'))
const state = require(path.join(ROOT, 'backend/services/state.js'))

function caddyAvailable() {
  try { execFileSync('caddy', ['version'], { timeout: 5000 }); return true } catch { return false }
}
const HAVE_CADDY = caddyAvailable()

// ── fixtures ──────────────────────────────────────────────────────────

function ps({ id, name, image, running = true }) {
  return { ID: id, Names: name, Image: image, State: running ? 'running' : 'exited', Status: running ? 'Up 2 minutes' : 'Exited (0) 1 minute ago' }
}

function inspect({ id, name, image, env = [], labels = {}, ports = {}, exposed = {}, networks = {}, running = true, cmd = null }) {
  return {
    Id: id,
    Name: '/' + name,
    Config: { Image: image, Env: env, Labels: labels, Cmd: cmd, ExposedPorts: exposed },
    State: { Running: running },
    NetworkSettings: { Ports: ports, Networks: networks },
  }
}

function published(containerPort, hostPort) {
  return { [`${containerPort}/tcp`]: [{ HostIp: '0.0.0.0', HostPort: String(hostPort) }] }
}
function exposedOnly(containerPort) {
  return { [`${containerPort}/tcp`]: {} }
}

// Fake docker client — implements the exact interface discovery/index.js
// expects from discovery/docker.js's createDockerClient().
function fakeClient({ available = true, code = null, message = null, containers = [] }) {
  const byId = new Map(containers.map(c => [c.id, c]))
  return {
    isAvailable: () => (available ? { ok: true } : { ok: false, code, message }),
    listContainers: () => ({ ok: true, containers: containers.map(c => c.ps) }),
    inspectContainer: id => {
      const c = byId.get(id)
      if (!c) return null
      return c.inspectFails ? null : c.inspect
    },
    inspectNetwork: () => null,
    topProcesses: id => {
      const c = byId.get(id)
      return c ? (c.processes || []) : null
    },
    // Dispatches on the probe being run: discovery/php.js sends a
    // `[ -e ... ]` filesystem probe, everything else is a web-server config
    // dump (nginx -T, apachectl -S, cat of config paths, ...).
    execCapture: (id, cmd) => {
      const c = byId.get(id)
      if (!c) return { ok: false, stdout: '' }
      if (!/\[ -e /.test(cmd)) {
        if (!c.serverConfig) return { ok: false, stdout: '' }
        return { ok: true, stdout: c.serverConfig }
      }
      if (!c.fsHits) return { ok: false, stdout: '' }
      const root = c.docRoot || '/var/www/html'
      return { ok: true, stdout: c.fsHits.map(h => `${h}:${root}`).join('\n') }
    },
    execTest: () => false,
  }
}

// ── Docker availability ──────────────────────────────────────────────

section('Docker unavailable')
;(async () => {
  {
    const client = fakeClient({ available: false, code: 'DAEMON_UNAVAILABLE', message: 'Docker daemon is not reachable.' })
    const report = await discovery.discover({ dockerClient: client })
    check('reports not ok', report.ok === false)
    check('carries a code', report.code === 'DAEMON_UNAVAILABLE')
    check('carries a human message', /not reachable/.test(report.message))
    check('containers is empty, not thrown', Array.isArray(report.containers) && report.containers.length === 0)
  }

  section('Docker permission denied')
  {
    const client = fakeClient({ available: false, code: 'PERMISSION_DENIED', message: 'Permission denied talking to the Docker daemon.' })
    const report = await discovery.discover({ dockerClient: client })
    check('reports not ok', report.ok === false)
    check('carries PERMISSION_DENIED code', report.code === 'PERMISSION_DENIED')
  }

  // ── PHP / runtime detection ─────────────────────────────────────────

  section('PHP container detection (image + fs signals)')
  {
    const c = {
      id: 'c1',
      ps: ps({ id: 'c1', name: 'store', image: 'php:8.3-fpm' }),
      inspect: inspect({
        id: 'c1', name: 'store', image: 'php:8.3-fpm',
        ports: published(80, 8080),
        networks: { catwaf_default: { IPAddress: '172.18.0.2', Aliases: ['store'] } },
      }),
      processes: ['1 root php-fpm: master process'],
      fsHits: ['index.php', 'composer.json', 'vendor'],
    }
    const client = fakeClient({ containers: [c] })
    const report = await discovery.discover({ dockerClient: client, skipHttpProbe: true })
    check('discovery ok', report.ok === true)
    check('found one container', report.containers.length === 1)
    const store = report.containers[0]
    check('classified as PHP', store.php.isPhp === true, store.php)
    check('high confidence (image +40, fs +30)', store.php.confidence >= 70, store.php.confidence)
    check('is a web app', store.web.isWeb === true)
    check('web port is 80 (container) / 8080 (host)', store.web.port === 80 && store.web.hostPort === 8080)
  }

  section('PHP-FPM process signal specifically')
  {
    const c = {
      id: 'c2',
      ps: ps({ id: 'c2', name: 'fpm-only', image: 'some/custom-base' }),
      inspect: inspect({ id: 'c2', name: 'fpm-only', image: 'some/custom-base', ports: published(9000, 9000) }),
      processes: ['1 root php-fpm: master process', '7 www-data php-fpm: pool www'],
    }
    const client = fakeClient({ containers: [c] })
    const report = await discovery.discover({ dockerClient: client, skipHttpProbe: true })
    const ctr = report.containers[0]
    check('php-fpm process detected', ctr.php.evidence.some(e => e.signal === 'process' && /php-fpm/.test(e.detail)))
    check('php-fpm contributes 40 points', ctr.php.evidence.find(e => e.signal === 'process').points === 40)
  }

  section('Nginx + PHP detection')
  {
    const c = {
      id: 'c3',
      ps: ps({ id: 'c3', name: 'nginx-php', image: 'php:8.2-fpm' }),
      inspect: inspect({ id: 'c3', name: 'nginx-php', image: 'php:8.2-fpm', ports: published(80, 8082) }),
      processes: ['1 root nginx: master process', '2 www-data nginx: worker process', '3 www-data php-fpm: pool www'],
      fsHits: ['index.php'],
    }
    const client = fakeClient({ containers: [c] })
    const report = await discovery.discover({ dockerClient: client, skipHttpProbe: true })
    const ctr = report.containers[0]
    check('web server detected as nginx', ctr.server.server === 'nginx')
    check('classified as PHP', ctr.php.isPhp === true)
    check('runtime label mentions PHP', /PHP/.test(ctr.runtime.label))
  }

  section('Apache + PHP detection')
  {
    const c = {
      id: 'c4',
      ps: ps({ id: 'c4', name: 'apache-php', image: 'php:8.1-apache' }),
      inspect: inspect({ id: 'c4', name: 'apache-php', image: 'php:8.1-apache', ports: published(80, 8083) }),
      processes: ['1 root apache2 -DFOREGROUND', '2 www-data apache2 -DFOREGROUND'],
      fsHits: ['index.php'],
    }
    const client = fakeClient({ containers: [c] })
    const report = await discovery.discover({ dockerClient: client, skipHttpProbe: true })
    const ctr = report.containers[0]
    check('web server detected as apache', ctr.server.server === 'apache')
    check('classified as PHP', ctr.php.isPhp === true)
  }

  section('Laravel detection')
  {
    const c = {
      id: 'c5',
      ps: ps({ id: 'c5', name: 'laravel-app', image: 'php:8.3-fpm' }),
      inspect: inspect({ id: 'c5', name: 'laravel-app', image: 'php:8.3-fpm', ports: published(80, 8084) }),
      processes: ['1 root php-fpm: master process'],
      fsHits: ['index.php', 'composer.json', 'vendor', 'artisan'],
    }
    const client = fakeClient({ containers: [c] })
    const report = await discovery.discover({ dockerClient: client, skipHttpProbe: true })
    const ctr = report.containers[0]
    check('framework detected as Laravel', ctr.php.framework === 'Laravel')
  }

  section('WordPress detection (filesystem + env)')
  {
    const c1 = {
      id: 'c6',
      ps: ps({ id: 'c6', name: 'wp-fs', image: 'wordpress:6-php8.2-fpm' }),
      inspect: inspect({ id: 'c6', name: 'wp-fs', image: 'wordpress:6-php8.2-fpm', ports: published(80, 8085) }),
      processes: ['1 root php-fpm: master process'],
      fsHits: ['index.php', 'wp-config.php'],
    }
    const c2 = {
      id: 'c7',
      ps: ps({ id: 'c7', name: 'wp-env', image: 'wordpress:6-php8.2-fpm' }),
      inspect: inspect({
        id: 'c7', name: 'wp-env', image: 'wordpress:6-php8.2-fpm', ports: published(80, 8086),
        env: ['WORDPRESS_DB_HOST=db', 'WORDPRESS_DB_USER=wp'],
      }),
      processes: ['1 root php-fpm: master process'],
    }
    const client = fakeClient({ containers: [c1, c2] })
    const report = await discovery.discover({ dockerClient: client, skipHttpProbe: true })
    check('WordPress detected via filesystem', report.containers[0].php.framework === 'WordPress')
    check('WordPress detected via env vars', report.containers[1].php.framework === 'WordPress')
  }

  section('Node.js detection')
  {
    const c = {
      id: 'c8',
      ps: ps({ id: 'c8', name: 'api', image: 'node:22-alpine' }),
      inspect: inspect({ id: 'c8', name: 'api', image: 'node:22-alpine', ports: published(3000, 3000) }),
      processes: ['1 node server.js'],
    }
    const client = fakeClient({ containers: [c] })
    const report = await discovery.discover({ dockerClient: client, skipHttpProbe: true })
    const ctr = report.containers[0]
    check('not classified as PHP', ctr.php.isPhp === false)
    check('runtime detected as Node.js', ctr.runtime.type === 'node' && ctr.runtime.label === 'Node.js')
    check('version extracted from image tag', ctr.runtime.version === '22')
  }

  section('Non-web container detection (redis)')
  {
    const c = {
      id: 'c9',
      ps: ps({ id: 'c9', name: 'redis', image: 'redis:7-alpine' }),
      inspect: inspect({ id: 'c9', name: 'redis', image: 'redis:7-alpine', exposed: exposedOnly(6379) }),
      processes: ['1 redis-server *:6379'],
    }
    const client = fakeClient({ containers: [c] })
    const report = await discovery.discover({ dockerClient: client, skipHttpProbe: true })
    const ctr = report.containers[0]
    check('flagged as infra image', ctr.infraHint === true)
    check('not detected as a web app', ctr.web.isWeb === false)
    check('excluded from webApps', report.webApps.length === 0)
  }

  section('Multiple web containers + multiple exposed ports')
  {
    const store = {
      id: 'c10',
      ps: ps({ id: 'c10', name: 'store', image: 'php:8.3-fpm' }),
      inspect: inspect({ id: 'c10', name: 'store', image: 'php:8.3-fpm', ports: published(80, 8090) }),
      processes: ['1 php-fpm: master process'],
      fsHits: ['index.php'],
    }
    const api = {
      id: 'c11',
      ps: ps({ id: 'c11', name: 'api', image: 'node:20-alpine' }),
      inspect: inspect({
        id: 'c11', name: 'api', image: 'node:20-alpine',
        ports: { ...published(3000, 3001), ...published(9229, 9229) }, // app port + debug port
      }),
      processes: ['1 node server.js'],
    }
    const client = fakeClient({ containers: [store, api] })
    const report = await discovery.discover({ dockerClient: client, skipHttpProbe: true })
    check('two containers scanned', report.containers.length === 2)
    check('both are web apps', report.webApps.length === 2)
    const apiCtr = report.containers.find(c => c.name === 'api')
    check('common HTTP port (3000) preferred over debug port (9229)', apiCtr.web.port === 3000, apiCtr.web)

    const { routes, skipped } = await routesSvc.planRoutes(report.webApps)
    check('a route planned for each web app', routes.length === 2, { routes, skipped })
    check('routes get distinct listen ports', new Set(routes.map(r => r.listenPort)).size === routes.length)
  }

  section('Malformed / incomplete Docker metadata')
  {
    const c = {
      id: 'c12',
      ps: ps({ id: 'c12', name: 'vanished', image: 'php:8.3-fpm' }),
      inspect: null,
      inspectFails: true,
    }
    const client = fakeClient({ containers: [c] })
    const report = await discovery.discover({ dockerClient: client, skipHttpProbe: true })
    check('scan does not throw / fails softly', report.ok === true)
    check('container reported with incomplete flag', report.containers[0].incomplete === true)
    check('not counted as a web app', report.webApps.length === 0)
  }

  // ── Split nginx + PHP-FPM correlation ────────────────────────────────
  // Regression: these two containers are only a PHP web app *together*.
  // Looked at alone, nginx has no PHP on it and php-fpm speaks no HTTP.

  const NGINX_PHP_CONF = [
    'server {',
    '    listen 80;',
    '    root /var/www/html;',
    '    location ~ \\.php$ {',
    '        fastcgi_pass freshmart_php:9000;',
    '        fastcgi_index index.php;',
    '    }',
    '}',
  ].join('\n')

  function freshmartStack({ nginxConfig = NGINX_PHP_CONF, nginxFsHits = null, extraPhp = false } = {}) {
    const net = { 'fake-web_freshmart': { IPAddress: '172.20.0.3', Aliases: ['nginx'] } }
    const phpNet = { 'fake-web_freshmart': { IPAddress: '172.20.0.4', Aliases: ['php'] } }

    const stack = [
      {
        id: 'fm1',
        ps: ps({ id: 'fm1', name: 'freshmart_nginx', image: 'nginx:1.25-alpine' }),
        inspect: inspect({
          id: 'fm1', name: 'freshmart_nginx', image: 'nginx:1.25-alpine',
          labels: { 'com.docker.compose.service': 'nginx', 'com.docker.compose.project': 'fake-web' },
          // Mirrors test/fixtures/nginx-php-fpm: internal-only, no host
          // port mapping. Discovery must find it on the Docker network.
          exposed: exposedOnly(80), networks: net,
        }),
        processes: ['1 root nginx: master process nginx -g daemon off;', '7 nginx nginx: worker process'],
        serverConfig: nginxConfig,
        fsHits: nginxFsHits,
      },
      {
        id: 'fm2',
        ps: ps({ id: 'fm2', name: 'freshmart_php', image: 'fake-web-php' }),
        inspect: inspect({
          id: 'fm2', name: 'freshmart_php', image: 'fake-web-php',
          labels: { 'com.docker.compose.service': 'php', 'com.docker.compose.project': 'fake-web' },
          exposed: exposedOnly(9000), networks: phpNet,
          // Custom image name carries no version — the official php images
          // set PHP_VERSION, which is where the version has to come from.
          env: ['PHP_VERSION=8.3.28'],
        }),
        processes: ['1 root php-fpm: master process (/usr/local/etc/php-fpm.conf)', '8 www-data php-fpm: pool www'],
        fsHits: ['index.php', 'composer.json'],
      },
      {
        id: 'fm3',
        ps: ps({ id: 'fm3', name: 'freshmart_db', image: 'mariadb:10.11' }),
        inspect: inspect({
          id: 'fm3', name: 'freshmart_db', image: 'mariadb:10.11',
          labels: { 'com.docker.compose.service': 'db', 'com.docker.compose.project': 'fake-web' },
          exposed: exposedOnly(3306), networks: phpNet,
        }),
        processes: ['1 mysql mariadbd'],
      },
    ]

    if (extraPhp) {
      stack.push({
        id: 'fm4',
        ps: ps({ id: 'fm4', name: 'freshmart_php2', image: 'php:8.3-fpm' }),
        inspect: inspect({
          id: 'fm4', name: 'freshmart_php2', image: 'php:8.3-fpm',
          labels: { 'com.docker.compose.service': 'php2' },
          exposed: exposedOnly(9000), networks: phpNet,
        }),
        processes: ['1 root php-fpm: master process'],
      })
    }
    return stack
  }

  section('Separate nginx + PHP-FPM containers correlate (the live-test regression)')
  {
    const client = fakeClient({ containers: freshmartStack() })
    const report = await discovery.discover({ dockerClient: client, skipHttpProbe: true })

    const nginx = report.containers.find(c => c.name === 'freshmart_nginx')
    const php = report.containers.find(c => c.name === 'freshmart_php')
    const db = report.containers.find(c => c.name === 'freshmart_db')

    check('nginx is classified as PHP, not static', nginx.php.isPhp === true, nginx.php)
    check('nginx runtime label is PHP', /^PHP/.test(nginx.runtime.label), nginx.runtime)
    check('PHP version comes from the backend PHP_VERSION env var', nginx.runtime.label === 'PHP 8.3', nginx.runtime)
    check('nginx keeps its web server identity', nginx.server.server === 'nginx')
    check('correlation basis is the config, not a guess', nginx.fastcgi?.basis === 'config', nginx.fastcgi)
    check('backend target recorded', nginx.fastcgi?.target === 'freshmart_php:9000', nginx.fastcgi)
    check('backend name recorded', nginx.fastcgi?.backendName === 'php', nginx.fastcgi)
    check('config signal is in the PHP evidence', nginx.php.evidence.some(e => e.signal === 'fastcgi' && e.points === 45))
    check('nginx is still the routable web app', nginx.web.isWeb === true)

    check('php container marked as an FPM backend', php.fpm?.isBackend === true)
    check('php container records who it serves', php.fpm?.servesFor.includes('nginx'), php.fpm)
    check('php container is NOT a routable web app', php.web.isWeb === false)

    check('db is not a web app', db.web.isWeb === false)
    check('db is not an FPM backend', !db.fpm)

    check('exactly one routable web app in the stack', report.webApps.length === 1)
    check('the routable one is nginx', report.webApps[0].name === 'freshmart_nginx')

    const { routes } = await routesSvc.planRoutes(report.webApps)
    check('nginx port is the internal container port', nginx.web.port === 80 && nginx.web.hostPort === null, nginx.web)
    check('nginx reachability is docker-internal', nginx.web.reachability === 'docker-internal', nginx.web)
    check('one route planned', routes.length === 1, routes)
    check('route points at the nginx container, not php-fpm', routes[0].upstream === 'nginx:80', routes[0])
    check('route carries the PHP runtime', /PHP/.test(routes[0].runtime || ''), routes[0])
  }

  section('Docker-internal nginx (no published host port) is still a web app')
  {
    // Regression: a container must not need a host port mapping to count as
    // a web application. nginx on an internal :80 is reachable by Caddy over
    // the Docker network, and is in fact the safer deployment — there is no
    // bypass path around the WAF.
    const c = {
      id: 'int1',
      ps: ps({ id: 'int1', name: 'internal_nginx', image: 'nginx:1.25-alpine' }),
      inspect: inspect({
        id: 'int1', name: 'internal_nginx', image: 'nginx:1.25-alpine',
        labels: { 'com.docker.compose.service': 'nginx' },
        exposed: exposedOnly(80),
        networks: { 'fake-web_freshmart': { IPAddress: '172.20.0.3', Aliases: ['nginx'] } },
      }),
      processes: ['1 root nginx: master process', '7 nginx nginx: worker process'],
      serverConfig: 'server { listen 80; root /usr/share/nginx/html; }',
    }
    const client = fakeClient({ containers: [c] })
    const report = await discovery.discover({ dockerClient: client, skipHttpProbe: true })
    const ctr = report.containers[0]

    check('detected as a web app without a published port', ctr.web.isWeb === true, ctr.web)
    check('reachability is docker-internal', ctr.web.reachability === 'docker-internal', ctr.web)
    check('published is false', ctr.web.published === false)
    check('exposed is true', ctr.web.exposed === true)
    check('port is the container port, not a host port', ctr.web.port === 80 && ctr.web.hostPort === null)
    check('network alias recorded', ctr.web.networkAliases.includes('fake-web_freshmart'), ctr.web)
    check('no HTTP probe attempted for an internal port', ctr.web.httpCheck === null)

    const { routes, skipped } = await routesSvc.planRoutes(report.webApps)
    check('a route is planned', routes.length === 1, { routes, skipped })
    check('upstream uses the network alias, not a host port', routes[0].upstream === 'nginx:80', routes[0])
    check('route records docker-internal reachability', routes[0].reachability === 'docker-internal')
    check('no host-bypass warning for an unpublished container',
      !routes[0].warnings.some(w => /bypass/i.test(w)), routes[0].warnings)
    check('warning explains Caddy must join the network',
      routes[0].warnings.some(w => /attached to that network/i.test(w)), routes[0].warnings)
  }

  section('Host-published container keeps its bypass warning')
  {
    const c = {
      id: 'pub1',
      ps: ps({ id: 'pub1', name: 'published_nginx', image: 'nginx:1.25-alpine' }),
      inspect: inspect({
        id: 'pub1', name: 'published_nginx', image: 'nginx:1.25-alpine',
        labels: { 'com.docker.compose.service': 'web' },
        ports: published(80, 8080),
        networks: { appnet: { IPAddress: '172.22.0.2', Aliases: ['web'] } },
      }),
      processes: ['1 root nginx: master process'],
      serverConfig: 'server { listen 80; }',
    }
    const client = fakeClient({ containers: [c] })
    const report = await discovery.discover({ dockerClient: client, skipHttpProbe: true })
    const ctr = report.containers[0]
    check('reachability is host-published', ctr.web.reachability === 'host-published', ctr.web)
    check('host port recorded', ctr.web.hostPort === 8080)

    const { routes } = await routesSvc.planRoutes(report.webApps)
    check('bypass warning is preserved when a host port IS published',
      routes[0].warnings.some(w => /bypass/i.test(w)), routes[0].warnings)
  }

  section('Internal port on no routable network is not routable')
  {
    // host/none networking gives no DNS alias for Caddy to reach, and
    // nothing is published — there is genuinely no way in.
    const c = {
      id: 'hostnet1',
      ps: ps({ id: 'hostnet1', name: 'hostnet_nginx', image: 'nginx:1.25-alpine' }),
      inspect: inspect({
        id: 'hostnet1', name: 'hostnet_nginx', image: 'nginx:1.25-alpine',
        exposed: exposedOnly(80),
        networks: { host: { IPAddress: '', Aliases: [] } },
      }),
      processes: ['1 root nginx: master process'],
    }
    const client = fakeClient({ containers: [c] })
    const report = await discovery.discover({ dockerClient: client, skipHttpProbe: true })
    const ctr = report.containers[0]
    check('not treated as routable', ctr.web.isWeb === false, ctr.web)
    check('reachability is none', ctr.web.reachability === 'none', ctr.web)
  }

  section('A published non-HTTP service is not mistaken for a web app')
  {
    // Regression: a bare published port used to score exactly at the old
    // threshold, so `ports: 5432:5432` on Postgres read as a web app.
    const c = {
      id: 'pg1',
      ps: ps({ id: 'pg1', name: 'postgres', image: 'postgres:16' }),
      inspect: inspect({
        id: 'pg1', name: 'postgres', image: 'postgres:16',
        ports: published(5432, 5432),
        networks: { appnet: { IPAddress: '172.22.0.9', Aliases: ['db'] } },
      }),
      processes: ['1 postgres postgres'],
    }
    const client = fakeClient({ containers: [c] })
    const report = await discovery.discover({ dockerClient: client, skipHttpProbe: true })
    check('published Postgres is not a web app', report.containers[0].web.isWeb === false, report.containers[0].web)
    check('no route planned for it', report.webApps.length === 0)
  }

  section('Docker-internal Node service is discovered too')
  {
    const c = {
      id: 'nint1',
      ps: ps({ id: 'nint1', name: 'internal_api', image: 'node:22-alpine' }),
      inspect: inspect({
        id: 'nint1', name: 'internal_api', image: 'node:22-alpine',
        labels: { 'com.docker.compose.service': 'api' },
        exposed: exposedOnly(3000),
        networks: { appnet: { IPAddress: '172.23.0.4', Aliases: ['api'] } },
      }),
      processes: ['1 node server.js'],
    }
    const client = fakeClient({ containers: [c] })
    const report = await discovery.discover({ dockerClient: client, skipHttpProbe: true })
    const ctr = report.containers[0]
    check('internal Node service detected as a web app', ctr.web.isWeb === true, ctr.web)
    check('runtime still Node.js', ctr.runtime.type === 'node')
    const { routes } = await routesSvc.planRoutes(report.webApps)
    check('routes to the node service by alias', routes[0].upstream === 'api:3000', routes[0])
  }

  section('Static nginx stays static (no false PHP classification)')
  {
    const staticConf = 'server {\n    listen 80;\n    root /usr/share/nginx/html;\n    index index.html;\n}'
    const c = {
      id: 's1',
      ps: ps({ id: 's1', name: 'marketing-site', image: 'nginx:1.25-alpine' }),
      inspect: inspect({ id: 's1', name: 'marketing-site', image: 'nginx:1.25-alpine', ports: published(80, 8070) }),
      processes: ['1 root nginx: master process', '7 nginx nginx: worker process'],
      serverConfig: staticConf,
    }
    const client = fakeClient({ containers: [c] })
    const report = await discovery.discover({ dockerClient: client, skipHttpProbe: true })
    const ctr = report.containers[0]
    check('not classified as PHP', ctr.php.isPhp === false, ctr.php)
    check('runtime is static', ctr.runtime.type === 'static', ctr.runtime)
    check('no fastcgi correlation recorded', !ctr.fastcgi)
    check('still detected as a web app', ctr.web.isWeb === true)
  }

  section('nginx with a readable config and no fastcgi_pass stays static even beside a PHP-FPM container')
  {
    // The config IS readable and contains no fastcgi_pass, so the network
    // fallback must NOT kick in — this nginx genuinely serves static files.
    const staticConf = 'server {\n    listen 80;\n    root /usr/share/nginx/html;\n}'
    const stack = freshmartStack({ nginxConfig: staticConf })
    const client = fakeClient({ containers: stack })
    const report = await discovery.discover({ dockerClient: client, skipHttpProbe: true })
    const nginx = report.containers.find(c => c.name === 'freshmart_nginx')
    check('no correlation invented from network membership', !nginx.fastcgi, nginx.fastcgi)
    check('stays static', nginx.php.isPhp === false && nginx.runtime.type === 'static', nginx.runtime)
  }

  section('Unreadable config falls back to network inference (needs corroboration)')
  {
    // Config cannot be read (serverConfig: null). Exactly one PHP-FPM
    // container shares the network, and a shared webroot volume puts
    // index.php in the nginx container too — inference (+25) plus the
    // webserver (+10) and index.php (+15) signals clear the threshold.
    const stack = freshmartStack({ nginxConfig: null, nginxFsHits: ['index.php'] })
    const client = fakeClient({ containers: stack })
    const report = await discovery.discover({ dockerClient: client, skipHttpProbe: true })
    const nginx = report.containers.find(c => c.name === 'freshmart_nginx')
    check('correlation basis is network-inference', nginx.fastcgi?.basis === 'network-inference', nginx.fastcgi)
    check('inferred backend target recorded', nginx.fastcgi?.target === 'php:9000', nginx.fastcgi)
    check('classified as PHP with corroboration', nginx.php.isPhp === true, nginx.php)
    check('inference is worth fewer points than config', nginx.php.evidence.find(e => e.signal === 'fastcgi').points === 25)
  }

  section('Network inference alone is NOT enough to call something PHP')
  {
    // Same as above but with no corroborating filesystem signal: 25 + 10
    // = 35, below the 40 threshold. Deliberate — a PHP-FPM container
    // merely sharing a network is not proof this nginx serves PHP.
    const stack = freshmartStack({ nginxConfig: null, nginxFsHits: null })
    const client = fakeClient({ containers: stack })
    const report = await discovery.discover({ dockerClient: client, skipHttpProbe: true })
    const nginx = report.containers.find(c => c.name === 'freshmart_nginx')
    check('not classified as PHP on inference alone', nginx.php.isPhp === false, nginx.php)
    check('stays static', nginx.runtime.type === 'static')
  }

  section('Ambiguous topology produces no link')
  {
    // Config unreadable AND two PHP-FPM containers on the network — there
    // is no basis to pick one, so nothing is inferred.
    const stack = freshmartStack({ nginxConfig: null, extraPhp: true })
    const client = fakeClient({ containers: stack })
    const report = await discovery.discover({ dockerClient: client, skipHttpProbe: true })
    const nginx = report.containers.find(c => c.name === 'freshmart_nginx')
    check('no backend guessed when ambiguous', !nginx.fastcgi, nginx.fastcgi)
    check('not classified as PHP', nginx.php.isPhp === false)
  }

  section('FastCGI config parsing forms')
  {
    const viaUpstream = [
      'upstream php-backend { server freshmart_php:9000; }',
      'server { location ~ \\.php$ { fastcgi_pass php-backend; } }',
    ].join('\n')
    const targets = fastcgiSvc.parseFastcgiTargets(viaUpstream)
    check('upstream block is resolved to a host:port', targets[0].host === 'freshmart_php' && targets[0].port === 9000, targets)

    const unixSock = 'location ~ \\.php$ { fastcgi_pass unix:/run/php/php8.3-fpm.sock; }'
    check('unix socket marked local', fastcgiSvc.parseFastcgiTargets(unixSock)[0].local === true)

    const loopback = 'location ~ \\.php$ { fastcgi_pass 127.0.0.1:9000; }'
    check('loopback marked local', fastcgiSvc.parseFastcgiTargets(loopback)[0].local === true)

    const apacheConf = 'SetHandler "proxy:fcgi://freshmart_php:9000"'
    const apacheTargets = fastcgiSvc.parseFastcgiTargets(apacheConf)
    check('apache fcgi:// parsed', apacheTargets[0].host === 'freshmart_php' && apacheTargets[0].port === 9000, apacheTargets)

    check('config with no fastcgi yields nothing', fastcgiSvc.parseFastcgiTargets('server { root /x; }').length === 0)
  }

  section('Apache + separate PHP-FPM container correlates')
  {
    const apacheConf = [
      '<VirtualHost *:80>',
      '    DocumentRoot /var/www/html',
      '    <FilesMatch \\.php$>',
      '        SetHandler "proxy:fcgi://shop_php:9000"',
      '    </FilesMatch>',
      '</VirtualHost>',
    ].join('\n')
    const net = { shopnet: { IPAddress: '172.21.0.2', Aliases: ['web'] } }
    const stack = [
      {
        id: 'ap1',
        ps: ps({ id: 'ap1', name: 'shop_apache', image: 'httpd:2.4' }),
        inspect: inspect({ id: 'ap1', name: 'shop_apache', image: 'httpd:2.4', ports: published(80, 8060), networks: net }),
        processes: ['1 root httpd -DFOREGROUND'],
        serverConfig: apacheConf,
      },
      {
        id: 'ap2',
        ps: ps({ id: 'ap2', name: 'shop_php', image: 'php:8.2-fpm' }),
        inspect: inspect({ id: 'ap2', name: 'shop_php', image: 'php:8.2-fpm', exposed: exposedOnly(9000), networks: net }),
        processes: ['1 root php-fpm: master process'],
      },
    ]
    const client = fakeClient({ containers: stack })
    const report = await discovery.discover({ dockerClient: client, skipHttpProbe: true })
    const apache = report.containers.find(c => c.name === 'shop_apache')
    const php = report.containers.find(c => c.name === 'shop_php')
    check('apache correlated to its FPM backend', apache.fastcgi?.basis === 'config', apache.fastcgi)
    check('apache classified as PHP', apache.php.isPhp === true)
    check('PHP version taken from the backend image', /8\.2/.test(apache.runtime.label), apache.runtime)
    check('backend excluded from web apps', php.web.isWeb === false)
  }

  section('Self-contained PHP container is unaffected by correlation')
  {
    // php:8.3-apache runs both the web server and PHP in one container —
    // it must keep working exactly as before, with no FPM backend link.
    const c = {
      id: 'sc1',
      ps: ps({ id: 'sc1', name: 'monolith', image: 'php:8.3-apache' }),
      inspect: inspect({ id: 'sc1', name: 'monolith', image: 'php:8.3-apache', ports: published(80, 8050) }),
      processes: ['1 root apache2 -DFOREGROUND', '9 www-data php-fpm: pool www'],
      serverConfig: 'SetHandler "proxy:fcgi://127.0.0.1:9000"',
      fsHits: ['index.php', 'composer.json'],
    }
    const client = fakeClient({ containers: [c] })
    const report = await discovery.discover({ dockerClient: client, skipHttpProbe: true })
    const ctr = report.containers[0]
    check('still classified as PHP', ctr.php.isPhp === true)
    check('local fastcgi recorded as local, no cross-container backend', ctr.fastcgi?.basis === 'local' && !ctr.fastcgi.backendName, ctr.fastcgi)
    check('remains a routable web app', ctr.web.isWeb === true)
  }

  // ── HTTP header / body signals (real loopback server, no Docker) ────

  section('HTTP header + body signal (X-Powered-By, WordPress body)')
  {
    const srv = http.createServer((req, res) => {
      res.setHeader('X-Powered-By', 'PHP/8.3.4')
      res.end('<html><body><script src="/wp-content/themes/x/app.js"></script></body></html>')
    })
    await new Promise(resolve => srv.listen(0, '127.0.0.1', resolve))
    const port = srv.address().port

    const c = {
      id: 'c13',
      ps: ps({ id: 'c13', name: 'header-test', image: 'some/unlabeled-base' }),
      inspect: inspect({ id: 'c13', name: 'header-test', image: 'some/unlabeled-base', ports: published(port, port) }),
      processes: [],
    }
    const client = fakeClient({ containers: [c] })
    const report = await discovery.discover({ dockerClient: client, skipHttpProbe: false })
    const ctr = report.containers[0]
    check('HTTP probe succeeded', ctr.web.httpCheck?.ok === true, ctr.web.httpCheck)
    check('X-Powered-By header contributes PHP signal', ctr.php.evidence.some(e => e.signal === 'http-header'))
    check('body fingerprint sets WordPress framework', ctr.php.framework === 'WordPress')

    await new Promise(resolve => srv.close(resolve))
  }

  // ── Config generation / validation / dry-run ─────────────────────────

  // ── Proxy network attachment (making the WAF reachable) ─────────────

  section('CatWAF proxy is attached to the app\'s Docker network')
  {
    const calls = []
    const client = {
      ...fakeClient({ containers: [] }),
      listContainers: () => ({
        ok: true,
        containers: [{ ID: 'cad1', Names: 'catwaf-caddy', Image: 'catwaf-caddy:latest', State: 'running' }],
      }),
      inspectContainer: id => (id === 'catwaf-caddy' || id === 'cad1')
        ? { Id: 'cad1', Name: '/catwaf-caddy', NetworkSettings: { Networks: { catwaf_default: {} } } }
        : null,
      networkConnect: (net, container) => { calls.push([net, container]); return { ok: true } },
    }

    const proxy = networkSvc.describeProxy(client)
    check('proxy container detected', proxy.container === 'catwaf-caddy', proxy)
    check('proxy networks listed', proxy.networks.includes('catwaf_default'), proxy)

    const container = {
      name: 'freshmart_nginx', composeService: 'nginx',
      web: { port: 80, published: false, networkAliases: ['fake-web_freshmart'], reachability: 'docker-internal' },
      networks: [{ name: 'fake-web_freshmart', ipAddress: '172.20.0.3' }],
    }
    const up = await networkSvc.resolveUpstream(container, { dockerClient: client, proxy, dryRun: false })
    check('upstream uses the service name', up.target === 'nginx:80', up)
    check('proxy was attached to the app network', calls.length === 1 && calls[0][0] === 'fake-web_freshmart', calls)
    check('attachment reported', up.attached === 'attached', up)

    // Second call must not re-attach — describeProxy's network list was updated.
    const up2 = await networkSvc.resolveUpstream(container, { dockerClient: client, proxy, dryRun: false })
    check('re-resolving does not attach again (idempotent)', calls.length === 1, calls)
    check('still resolves to the same upstream', up2.target === 'nginx:80')
  }

  section('--dry-run never attaches a network')
  {
    const calls = []
    const client = {
      ...fakeClient({ containers: [] }),
      listContainers: () => ({ ok: true, containers: [{ ID: 'cad1', Names: 'catwaf-caddy', Image: 'catwaf-caddy', State: 'running' }] }),
      inspectContainer: () => ({ Id: 'cad1', Name: '/catwaf-caddy', NetworkSettings: { Networks: { catwaf_default: {} } } }),
      networkConnect: (net, cont) => { calls.push([net, cont]); return { ok: true } },
    }
    const proxy = networkSvc.describeProxy(client)
    const container = {
      name: 'app', composeService: 'app',
      web: { port: 80, published: false, networkAliases: ['appnet'], reachability: 'docker-internal' },
      networks: [{ name: 'appnet', ipAddress: '172.30.0.2' }],
    }
    const up = await networkSvc.resolveUpstream(container, { dockerClient: client, proxy, dryRun: true })
    check('no network mutation during dry-run', calls.length === 0, calls)
    check('dry-run reports the intended attachment', up.attached === 'would-attach', up)
  }

  section('Host-native CatWAF + Docker bridge + internal-only nginx:80 (live regression)')
  {
    // The exact failing case: CatWAF running directly on the host, nginx
    // inside a normal bridge network with NO published port. A host process
    // cannot resolve Docker's embedded DNS, so the upstream must be the
    // container IP — never `nginx:80`.
    const listener = http.createServer((q, s) => s.end('ok'))
    await new Promise(r => listener.listen(19471, '127.0.0.1', r))

    const record = {
      id: 'fm1', name: 'freshmart_nginx', composeService: 'nginx', composeProject: 'fake-web',
      image: 'nginx:1.25-alpine',
      networks: [{ name: 'fake-web_freshmart', ipAddress: '127.0.0.1', aliases: ['nginx'] }],
      ports: [{ containerPort: 19471, protocol: 'tcp', published: false, hostPort: null }],
      web: { port: 19471, published: false, hostPort: null, networkAliases: ['fake-web_freshmart'], reachability: 'docker-internal', isWeb: true },
    }
    const client = {
      inspectContainer: () => ({ NetworkSettings: { Networks: { 'fake-web_freshmart': { IPAddress: '127.0.0.1' } } } }),
      inspectNetwork: () => ({ Driver: 'bridge', Internal: false, Containers: {} }),
    }
    const proxy = { container: null, networks: [], inContainer: false, source: null }

    const up = await networkSvc.resolveUpstream(record, { dockerClient: client, proxy })
    check('an upstream IS resolved (was null before the fix)', !!up && !up.unreachable, up)
    check('upstream is the container IP, not the Docker DNS name', up.basis === 'container-ip', up)
    check('upstream does NOT use the service name', !/^nginx:/.test(up.target), up.target)
    check('upstream targets ip:containerPort', up.target === '127.0.0.1:19471', up.target)
    check('reachability was actually proven, not assumed', up.verified === true, up)
    check('flagged volatile (container IPs churn)', up.volatile === true)

    // And it must produce a real route, not a "skipped" entry.
    const { routes, skipped } = await routesSvc.planRoutes([record], {
      resolveUpstream: ctr => networkSvc.resolveUpstream(ctr, { dockerClient: client, proxy }),
    })
    check('a route is planned (was skipped before the fix)', routes.length === 1, { routes, skipped })
    check('route upstream is the container IP', routes[0].upstream === '127.0.0.1:19471', routes[0])

    await new Promise(r => listener.close(r))
  }

  section('Container IP is found even when NetworkSettings.IPAddress is empty')
  {
    // Some daemons leave the per-endpoint IPAddress blank; the network's
    // own member list still knows the address. Reading only one field made
    // a reachable container look unroutable.
    const listener = http.createServer((q, s) => s.end('ok'))
    await new Promise(r => listener.listen(19472, '127.0.0.1', r))

    const record = {
      id: 'fm9', name: 'freshmart_nginx', composeService: 'nginx',
      image: 'nginx:alpine',
      networks: [{ name: 'appnet', ipAddress: null, aliases: ['nginx'] }],
      ports: [{ containerPort: 19472, protocol: 'tcp', published: false, hostPort: null }],
      web: { port: 19472, published: false, hostPort: null, networkAliases: ['appnet'], reachability: 'docker-internal', isWeb: true },
    }
    const client = {
      inspectContainer: () => ({ NetworkSettings: { IPAddress: '', Networks: { appnet: { IPAddress: '' } } } }),
      inspectNetwork: () => ({
        Driver: 'bridge', Internal: false,
        Containers: { fm9: { Name: 'freshmart_nginx', IPv4Address: '127.0.0.1/16' } },
      }),
    }
    const up = await networkSvc.resolveUpstream(record, { dockerClient: client, proxy: { container: null, networks: [] } })
    check('address recovered from docker network inspect', up.target === '127.0.0.1:19472', up)
    check('CIDR suffix stripped', !/\//.test(up.target))

    await new Promise(r => listener.close(r))
  }

  section('Unreachable container IPs are refused with a specific reason')
  {
    const base = {
      id: 'x1', name: 'app', composeService: 'app', image: 'nginx',
      networks: [{ name: 'appnet', ipAddress: '127.0.0.1' }],
      ports: [{ containerPort: 19479, protocol: 'tcp', published: false, hostPort: null }],
      web: { port: 19479, published: false, hostPort: null, networkAliases: ['appnet'], reachability: 'docker-internal', isWeb: true },
    }
    const proxy = { container: null, networks: [] }

    // nothing listening on 19479
    const dead = await networkSvc.resolveUpstream(base, {
      dockerClient: {
        inspectContainer: () => ({ NetworkSettings: { Networks: { appnet: { IPAddress: '127.0.0.1' } } } }),
        inspectNetwork: () => ({ Driver: 'bridge', Internal: false, Containers: {} }),
      },
      proxy,
    })
    check('port not listening -> unreachable', dead.unreachable === true, dead)
    check('diagnosis names the address and error', /127\.0\.0\.1:19479 is not reachable/.test(dead.diagnostics.join(';')), dead.diagnostics)

    const internal = await networkSvc.resolveUpstream(base, {
      dockerClient: {
        inspectContainer: () => ({ NetworkSettings: { Networks: { appnet: { IPAddress: '127.0.0.1' } } } }),
        inspectNetwork: () => ({ Driver: 'bridge', Internal: true, Containers: {} }),
      },
      proxy,
    })
    check('internal network -> unreachable with reason', internal.unreachable && /marked internal/.test(internal.diagnostics.join(';')), internal)

    const overlay = await networkSvc.resolveUpstream(base, {
      dockerClient: {
        inspectContainer: () => ({ NetworkSettings: { Networks: { appnet: { IPAddress: '127.0.0.1' } } } }),
        inspectNetwork: () => ({ Driver: 'overlay', Internal: false, Containers: {} }),
      },
      proxy,
    })
    check('non-routable driver -> unreachable with reason', overlay.unreachable && /overlay/.test(overlay.diagnostics.join(';')), overlay)

    const { skipped } = await routesSvc.planRoutes([base], {
      resolveUpstream: () => Promise.resolve(dead),
    })
    check('skip reason carries the diagnostics through to the user', /not reachable/.test(skipped[0].reason), skipped)
  }

  section('Containerized Caddy still routes by service name (unchanged)')
  {
    const calls = []
    const client = {
      listContainers: () => ({ ok: true, containers: [{ ID: 'cad1', Names: 'catwaf-caddy', Image: 'catwaf-caddy', State: 'Up 3 minutes' }] }),
      inspectContainer: () => ({ Id: 'cad1', NetworkSettings: { Networks: { catwaf_default: {} } } }),
      inspectNetwork: () => ({ Driver: 'bridge', Internal: false, Containers: {} }),
      networkConnect: (n, cn) => { calls.push([n, cn]); return { ok: true } },
    }
    const proxy = networkSvc.describeProxy(client)
    check('containerized proxy detected', proxy.container === 'catwaf-caddy', proxy)

    const record = {
      id: 'fm1', name: 'freshmart_nginx', composeService: 'nginx', image: 'nginx',
      networks: [{ name: 'fake-web_freshmart', ipAddress: '172.20.0.3' }],
      ports: [{ containerPort: 80, protocol: 'tcp', published: false, hostPort: null }],
      web: { port: 80, published: false, hostPort: null, networkAliases: ['fake-web_freshmart'], reachability: 'docker-internal', isWeb: true },
    }
    const up = await networkSvc.resolveUpstream(record, { dockerClient: client, proxy })
    check('routes by Docker service name', up.target === 'nginx:80', up)
    check('proxy attached to the app network', calls.length === 1 && calls[0][0] === 'fake-web_freshmart', calls)
    check('no container-IP fallback used', up.basis === 'docker-network-alias', up)
  }

  section('Host-installed proxy falls back correctly')
  {
    const client = {
      ...fakeClient({ containers: [] }),
      listContainers: () => ({ ok: true, containers: [] }),
      inspectContainer: () => null,
      networkConnect: () => ({ ok: false, error: 'no such container' }),
    }
    const proxy = networkSvc.describeProxy(client)
    check('no proxy container found', proxy.container === null)

    const publishedApp = {
      name: 'app', composeService: 'app',
      web: { port: 80, published: true, hostPort: 8080, networkAliases: ['appnet'], reachability: 'host-published' },
      networks: [{ name: 'appnet', ipAddress: '172.30.0.2' }],
    }
    const up1 = await networkSvc.resolveUpstream(publishedApp, { dockerClient: client, proxy })
    check('published app routed via host port', up1.target === '127.0.0.1:8080' && up1.basis === 'published-host-port', up1)

    const internalApp = {
      name: 'app2', composeService: 'app2',
      web: { port: 80, published: false, networkAliases: ['appnet'], reachability: 'docker-internal' },
      networks: [{ name: 'appnet', ipAddress: '172.30.0.9' }],
    }
    // verifyReachable:false exercises the address-selection logic alone;
    // the reachability probe itself is covered by its own section below.
    const up2 = await networkSvc.resolveUpstream(internalApp, { dockerClient: client, proxy, verifyReachable: false })
    check('internal app routed via container IP', up2.target === '172.30.0.9:80' && up2.basis === 'container-ip', up2)
    check('container-IP routing flagged volatile', up2.volatile === true, up2)

    // With verification on (the default), an address nothing answers on is
    // refused rather than written into the config.
    const up2verified = await networkSvc.resolveUpstream(internalApp, { dockerClient: client, proxy })
    check('unreachable container IP is refused when verification is on', up2verified.unreachable === true, up2verified)

    const unreachable = {
      name: 'app3', composeService: 'app3',
      web: { port: 80, published: false, networkAliases: [], reachability: 'none' },
      networks: [],
    }
    const noPath = await networkSvc.resolveUpstream(unreachable, { dockerClient: client, proxy })
    check('genuinely unreachable app yields no upstream', noPath.unreachable === true, noPath)
  }

  // ── Protection verification honesty ─────────────────────────────────

  section('verify.js does not call an unreachable route protected')
  {
    // Nothing is listening on this port.
    const v = await verifySvc.verifyRoute({ name: 'dead', listenPort: 19399, upstream: 'x:80' }, { attempts: 2, delayMs: 20 })
    check('not reported protected', v.protected === false, v)
    check('reason mentions no traffic can traverse', /no traffic can traverse|not answering/i.test(v.reason), v.reason)
  }

  section('verify.js reports an unreachable upstream as broken, not protected')
  {
    const srv = http.createServer((req, res) => { res.writeHead(502); res.end('bad gateway') })
    await new Promise(r => srv.listen(19398, '127.0.0.1', r))
    const v = await verifySvc.verifyRoute({ name: 'broken', listenPort: 19398, upstream: 'gone:80' }, { attempts: 2, delayMs: 20 })
    check('not reported protected', v.protected === false, v)
    check('flagged as upstream unreachable', v.upstreamUnreachable === true, v)
    await new Promise(r => srv.close(r))
  }

  // ── Idempotency / stable ports ──────────────────────────────────────

  section('Listen ports are stable across runs')
  {
    const webApp = {
      name: 'freshmart_nginx', composeService: 'nginx', composeProject: 'fake-web', id: 'fm1',
      web: { port: 80, published: false, networkAliases: ['fake-web_freshmart'], reachability: 'docker-internal' },
      networks: [{ name: 'fake-web_freshmart', ipAddress: '172.20.0.3' }],
      php: { isPhp: true, confidence: 70, framework: null }, runtime: { label: 'PHP 8.3' },
    }
    const store = {}
    const fakeDb = { getState: k => store[k], setState: (k, v) => { store[k] = v } }
    const resolve = () => ({ target: 'nginx:80', basis: 'docker-network-alias', network: 'fake-web_freshmart', attached: 'already' })

    const first = await routesSvc.planRoutes([webApp], { db: fakeDb, resolveUpstream: resolve })
    const firstPort = first.routes[0].listenPort
    check('a port was assigned', typeof firstPort === 'number')
    check('assignment persisted', !!store[routesSvc.PORT_ASSIGNMENT_KEY], store)

    const second = await routesSvc.planRoutes([webApp], { db: fakeDb, resolveUpstream: resolve })
    check('same port on re-run (endpoint does not move)', second.routes[0].listenPort === firstPort, { firstPort, second: second.routes[0].listenPort })

    // Regression: on a real re-run CatWAF is ALREADY listening on the
    // remembered port, so a naive "is this port free?" check rejects it and
    // silently moves the endpoint. Occupy the port and confirm it is kept.
    const squatter = http.createServer((q, s) => s.end('catwaf-itself'))
    await new Promise(r => squatter.listen(firstPort, '127.0.0.1', r))
    const third = await routesSvc.planRoutes([webApp], { db: fakeDb, resolveUpstream: resolve })
    check('remembered port is reused even while occupied by CatWAF itself',
      third.routes[0].listenPort === firstPort, { firstPort, third: third.routes[0].listenPort })
    await new Promise(r => squatter.close(r))

    // A different app must still get its own port, not steal that one.
    const other = { ...webApp, name: 'other_nginx', composeService: 'other', id: 'o1' }
    const both = await routesSvc.planRoutes([webApp, other], { db: fakeDb, resolveUpstream: resolve })
    check('a second app gets a distinct port', both.routes[0].listenPort !== both.routes[1].listenPort, both.routes.map(r => r.listenPort))
    check('the first app keeps its remembered port', both.routes[0].listenPort === firstPort, both.routes[0].listenPort)
  }

  section('Re-applying does not duplicate routes')
  {
    const before = fs.readFileSync(process.env.CADDYFILE_PATH, 'utf8')
    const route = {
      name: 'idem', containerName: 'idem', containerId: 'i1',
      listenPort: 8099, upstream: 'idem:80', upstreamBasis: 'docker-network-alias',
      framework: null, runtime: null, phpConfidence: null, warnings: [],
    }
    const merged1 = applySvc.mergeIntoCaddyfile(before, generatorSvc.buildAutoRegion([route], state.WAF))
    const merged2 = applySvc.mergeIntoCaddyfile(merged1, generatorSvc.buildAutoRegion([route], state.WAF))
    const count = (s, re) => (s.match(re) || []).length
    check('one AUTO region after first apply', count(merged1, /@@CATWAF_AUTO_START@@/g) === 1)
    check('still one AUTO region after re-apply', count(merged2, /@@CATWAF_AUTO_START@@/g) === 1)
    check('route not duplicated', count(merged2, /:8099 \{/g) === 1, count(merged2, /:8099 \{/g))
    check('unrelated config preserved', merged2.includes(':9990'))
  }

  section('A disappeared upstream is dropped, not left stale')
  {
    const withTwo = applySvc.mergeIntoCaddyfile(
      fs.readFileSync(process.env.CADDYFILE_PATH, 'utf8'),
      generatorSvc.buildAutoRegion([
        { name: 'a', containerName: 'a', listenPort: 8101, upstream: 'a:80', runtime: null, warnings: [] },
        { name: 'b', containerName: 'b', listenPort: 8102, upstream: 'b:80', runtime: null, warnings: [] },
      ], state.WAF))
    check('both routes present initially', withTwo.includes(':8101') && withTwo.includes(':8102'))

    // Container "b" is gone on the next run.
    const withOne = applySvc.mergeIntoCaddyfile(withTwo,
      generatorSvc.buildAutoRegion([
        { name: 'a', containerName: 'a', listenPort: 8101, upstream: 'a:80', runtime: null, warnings: [] },
      ], state.WAF))
    check('surviving route kept', withOne.includes(':8101'))
    check('vanished upstream route removed', !withOne.includes(':8102'))
    check('unrelated config still intact', withOne.includes(':9990'))
  }

  // ══════════════════════════════════════════════════════════════════
  // Apache
  // ══════════════════════════════════════════════════════════════════

  section('Apache recognition: naming variants and image families')
  {
    const probe = (image, procs, ports = [{ containerPort: 80 }]) =>
      webserversSvc.detect({ image, ports }, procs)

    // Debian ships apache2, RHEL/Fedora and the official image ship httpd.
    check('apache2 process detected', probe('scratch', ['1 root /usr/sbin/apache2 -DFOREGROUND'])?.id === 'apache')
    check('httpd process detected', probe('scratch', ['1 root httpd -DFOREGROUND'])?.id === 'apache')
    check('apachectl process detected', probe('scratch', ['1 root /usr/sbin/apachectl -k start'])?.id === 'apache')
    check('apache2ctl process detected', probe('scratch', ['1 root apache2ctl -DFOREGROUND'])?.id === 'apache')

    // Image families
    check('httpd:2.4 image detected', probe('httpd:2.4', [])?.id === 'apache')
    check('httpd:2.4-alpine image detected', probe('httpd:2.4-alpine', [])?.id === 'apache')
    check('bitnami/apache image detected', probe('bitnami/apache:2.4', [])?.id === 'apache')
    // The suffix family — the most common way Apache actually ships, and
    // exactly what a naive /(^|\/)apache(:|$)/ misses.
    check('php:8.3-apache image detected', probe('php:8.3-apache', [])?.id === 'apache')
    check('php:8.2-apache-bookworm image detected', probe('php:8.2-apache-bookworm', [])?.id === 'apache')
    check('wordpress:6-php8.2-apache image detected', probe('wordpress:6-php8.2-apache', [])?.id === 'apache')
    check('drupal:10-apache image detected', probe('drupal:10-apache', [])?.id === 'apache')

    // The Apache *Foundation* is not httpd — these must NOT match.
    check('apache/kafka is NOT a web server', probe('apache/kafka', ['java -jar kafka']) === null)
    check('apache/airflow is NOT a web server', probe('apache/airflow:2.9', []) === null)
    check('apache-tomcat process is NOT httpd', probe('scratch', ['/opt/apache-tomcat/bin/java -jar x']) === null)

    // Confidence
    const both = probe('httpd:2.4', ['1 root httpd -DFOREGROUND'])
    check('image + process + port 80 = 100 confidence', both.confidence === 100, both)
    check('label is human-readable', both.label === 'Apache', both.label)
    const imageOnly = probe('httpd:2.4', [], [{ containerPort: 7777 }])
    check('image alone is not full confidence', imageOnly.confidence === 45, imageOnly.confidence)
    const procOnly = probe('scratch', ['1 root httpd'], [{ containerPort: 7777 }])
    check('process alone outweighs image alone', procOnly.confidence === 55, procOnly.confidence)
    check('nginx is unaffected by the Apache patterns', probe('nginx:1.25-alpine', ['nginx: master process'])?.id === 'nginx')
  }

  section('Apache config parsing (Listen / DocumentRoot / VirtualHost / ProxyPass)')
  {
    const conf = [
      '# Listen 12.34.56.78:80', 'Listen 80', 'Listen 0.0.0.0:8081', 'Listen [::]:8443 https',
      '<VirtualHost *:8080>',
      '    DocumentRoot "/srv/myapp/public"',
      '    ProxyPassMatch ^/(.*\\.php)$ fcgi://app_php:9000/srv/myapp/public/$1',
      '    ProxyPass /api http://node_api:3000/',
      '</VirtualHost>',
    ].join('\n')
    const parsed = webserversSvc.parseServerConfig(conf)
    check('Listen ports parsed', [80, 8081, 8443].every(p => parsed.listens.includes(p)), parsed.listens)
    check('VirtualHost port parsed', parsed.listens.includes(8080), parsed.listens)
    check('commented-out Listen ignored', !parsed.listens.includes(12), parsed.listens)
    check('DocumentRoot parsed', parsed.documentRoots.includes('/srv/myapp/public'), parsed.documentRoots)
    check('http ProxyPass captured', parsed.httpProxies.includes('http://node_api:3000/'), parsed.httpProxies)
    check('fcgi:// is NOT treated as an http proxy', !parsed.httpProxies.some(u => /fcgi/.test(u)), parsed.httpProxies)
    check('fcgi:// IS seen as a FastCGI target', fastcgiSvc.parseFastcgiTargets(conf).some(t => t.host === 'app_php' && t.port === 9000))
    check('a config with nothing useful yields empty, not a throw', webserversSvc.parseServerConfig('   ').empty === true)
  }

  section('Apache HTTP port comes from its own Listen directive')
  {
    // A deliberately unconventional port: only the config knows it serves HTTP.
    const c = {
      id: 'ap-port',
      ps: ps({ id: 'ap-port', name: 'odd_apache', image: 'httpd:2.4' }),
      inspect: inspect({
        id: 'ap-port', name: 'odd_apache', image: 'httpd:2.4',
        labels: { 'com.docker.compose.service': 'web' },
        exposed: exposedOnly(7777),
        networks: { appnet: { IPAddress: '172.40.0.2', Aliases: ['web'] } },
      }),
      processes: ['1 root httpd -DFOREGROUND'],
      serverConfig: 'Listen 7777\nDocumentRoot "/var/www/html"',
    }
    const report = await discovery.discover({ dockerClient: fakeClient({ containers: [c] }), skipHttpProbe: true })
    const ctr = report.containers[0]
    check('detected as a web app on an unconventional port', ctr.web.isWeb === true, ctr.web)
    check('the Listen port is chosen', ctr.web.port === 7777, ctr.web.port)
    check('config evidence is recorded', ctr.web.evidence.some(e => /configuration listens on 7777/.test(e)), ctr.web.evidence)

    // Two exposed ports, config names one of them.
    const two = {
      id: 'ap-two',
      ps: ps({ id: 'ap-two', name: 'two_apache', image: 'httpd:2.4' }),
      inspect: inspect({
        id: 'ap-two', name: 'two_apache', image: 'httpd:2.4',
        exposed: { '7777/tcp': {}, '9999/tcp': {} },
        networks: { appnet: { IPAddress: '172.40.0.3', Aliases: ['two'] } },
      }),
      processes: ['1 root httpd -DFOREGROUND'],
      serverConfig: 'Listen 9999',
    }
    const r2 = await discovery.discover({ dockerClient: fakeClient({ containers: [two] }), skipHttpProbe: true })
    check('the configured port wins over the other exposed port', r2.containers[0].web.port === 9999, r2.containers[0].web.port)
  }

  section('Apache + separate PHP-FPM containers (split architecture)')
  {
    const apacheConf = [
      '<VirtualHost *:80>',
      '    DocumentRoot "/var/www/html"',
      '    <FilesMatch \\.php$>',
      '        SetHandler "proxy:fcgi://shop_php:9000"',
      '    </FilesMatch>',
      '</VirtualHost>',
    ].join('\n')
    const net = { 'shop_default': { IPAddress: '172.41.0.2', Aliases: ['web'] } }
    const stack = [
      {
        id: 'sa1',
        ps: ps({ id: 'sa1', name: 'shop_apache', image: 'httpd:2.4' }),
        inspect: inspect({
          id: 'sa1', name: 'shop_apache', image: 'httpd:2.4',
          labels: { 'com.docker.compose.service': 'web', 'com.docker.compose.project': 'shop' },
          exposed: exposedOnly(80), networks: net,
        }),
        processes: ['1 root httpd -DFOREGROUND', '8 www-data httpd -DFOREGROUND'],
        serverConfig: apacheConf,
      },
      {
        id: 'sa2',
        ps: ps({ id: 'sa2', name: 'shop_php', image: 'php:8.3-fpm-alpine' }),
        inspect: inspect({
          id: 'sa2', name: 'shop_php', image: 'php:8.3-fpm-alpine',
          labels: { 'com.docker.compose.service': 'php', 'com.docker.compose.project': 'shop' },
          exposed: exposedOnly(9000), networks: net, env: ['PHP_VERSION=8.3.28'],
        }),
        processes: ['1 root php-fpm: master process', '9 www-data php-fpm: pool www'],
        fsHits: ['index.php', 'composer.json'],
      },
      {
        id: 'sa3',
        ps: ps({ id: 'sa3', name: 'shop_db', image: 'mariadb:10.11' }),
        inspect: inspect({
          id: 'sa3', name: 'shop_db', image: 'mariadb:10.11',
          labels: { 'com.docker.compose.service': 'db' },
          exposed: exposedOnly(3306), networks: net,
        }),
        processes: ['1 mysql mariadbd'],
      },
    ]
    const report = await discovery.discover({ dockerClient: fakeClient({ containers: stack }), skipHttpProbe: true })
    const apache = report.containers.find(x => x.name === 'shop_apache')
    const php = report.containers.find(x => x.name === 'shop_php')
    const db = report.containers.find(x => x.name === 'shop_db')

    check('Apache identified', apache.server.server === 'apache' && apache.server.label === 'Apache', apache.server)
    check('Apache server confidence is 100', apache.server.confidence === 100, apache.server.confidence)
    check('Apache classified as PHP via FastCGI correlation', apache.php.isPhp === true, apache.php)
    check('correlation basis is the config', apache.fastcgi?.basis === 'config', apache.fastcgi)
    check('backend target recorded', apache.fastcgi?.target === 'shop_php:9000', apache.fastcgi)
    check('PHP version taken from the backend', apache.runtime.label === 'PHP 8.3', apache.runtime)
    check('Apache is the routable web app', apache.web.isWeb === true)
    check('Apache HTTP port is 80', apache.web.port === 80)

    check('PHP-FPM container marked as a backend', php.fpm?.isBackend === true)
    check('PHP-FPM records who it serves', php.fpm?.servesFor.includes('web'), php.fpm)
    check('PHP-FPM is NOT directly routable', php.web.isWeb === false, php.web)
    check('database is not a web app', db.web.isWeb === false)
    check('exactly one routable web app', report.webApps.length === 1)

    const { routes } = await routesSvc.planRoutes(report.webApps, {
      resolveUpstream: ctr => Promise.resolve({ target: `${ctr.composeService}:${ctr.web.port}`, basis: 'docker-network-alias', network: 'shop_default', attached: 'already' }),
    })
    check('one route generated, for Apache', routes.length === 1 && routes[0].containerName === 'shop_apache', routes)
    check('route upstream is the Apache container', routes[0].upstream === 'web:80', routes[0])
    check('route carries the PHP runtime', /PHP/.test(routes[0].runtime || ''), routes[0].runtime)
  }

  section('Apache serving static content only (PHP not mandatory)')
  {
    const c = {
      id: 'ap-static',
      ps: ps({ id: 'ap-static', name: 'brochure', image: 'httpd:2.4-alpine' }),
      inspect: inspect({
        id: 'ap-static', name: 'brochure', image: 'httpd:2.4-alpine',
        labels: { 'com.docker.compose.service': 'site' },
        exposed: exposedOnly(80),
        networks: { sitenet: { IPAddress: '172.42.0.2', Aliases: ['site'] } },
      }),
      processes: ['1 root httpd -DFOREGROUND'],
      serverConfig: 'Listen 80\nDocumentRoot "/usr/local/apache2/htdocs"',
    }
    const report = await discovery.discover({ dockerClient: fakeClient({ containers: [c] }), skipHttpProbe: true })
    const ctr = report.containers[0]
    check('detected as a web app', ctr.web.isWeb === true)
    check('NOT classified as PHP', ctr.php.isPhp === false, ctr.php)
    check('runtime is static', ctr.runtime.type === 'static', ctr.runtime)
    check('static label names Apache', /Apache/.test(ctr.runtime.label), ctr.runtime.label)
    check('no FastCGI correlation invented', !ctr.fastcgi)
    check('still protectable', report.webApps.length === 1)
  }

  section('Apache in front of a Node upstream (ProxyPass)')
  {
    const net = { 'appnet': { IPAddress: '172.43.0.2', Aliases: ['front'] } }
    const stack = [
      {
        id: 'apx1',
        ps: ps({ id: 'apx1', name: 'front_apache', image: 'httpd:2.4' }),
        inspect: inspect({
          id: 'apx1', name: 'front_apache', image: 'httpd:2.4',
          labels: { 'com.docker.compose.service': 'front' },
          exposed: exposedOnly(80), networks: net,
        }),
        processes: ['1 root httpd -DFOREGROUND'],
        serverConfig: '<VirtualHost *:80>\n  ProxyPass / http://api_node:3000/\n  ProxyPassReverse / http://api_node:3000/\n</VirtualHost>',
      },
      {
        id: 'apx2',
        ps: ps({ id: 'apx2', name: 'api_node', image: 'node:22-alpine' }),
        inspect: inspect({
          id: 'apx2', name: 'api_node', image: 'node:22-alpine',
          labels: { 'com.docker.compose.service': 'api' },
          exposed: exposedOnly(3000), networks: net,
        }),
        processes: ['1 node server.js'],
      },
    ]
    const report = await discovery.discover({ dockerClient: fakeClient({ containers: stack }), skipHttpProbe: true })
    const front = report.containers.find(x => x.name === 'front_apache')
    const api = report.containers.find(x => x.name === 'api_node')

    check('Apache front detected', front.server.server === 'apache')
    check('proxy backend resolved', front.httpProxy?.backendName === 'api', front.httpProxy)
    check('backend runtime identified as Node.js', front.httpProxy?.backendRuntime?.label === 'Node.js', front.httpProxy)
    check('Apache endpoint classified by what it serves, not as static', front.runtime.type === 'node', front.runtime)
    check('Apache is NOT misclassified as PHP', front.php.isPhp === false)
    check('the backend records who proxies it', (api.proxiedBy || []).includes('front'), api.proxiedBy)
  }

  section('Apache DocumentRoot drives the PHP filesystem probe')
  {
    // PHP lives in a non-standard webroot that only the config names.
    const c = {
      id: 'ap-root',
      ps: ps({ id: 'ap-root', name: 'oddroot', image: 'httpd:2.4' }),
      inspect: inspect({
        id: 'ap-root', name: 'oddroot', image: 'httpd:2.4',
        exposed: exposedOnly(80),
        networks: { rn: { IPAddress: '172.44.0.2', Aliases: ['oddroot'] } },
      }),
      processes: ['1 root httpd -DFOREGROUND', '5 www-data php-fpm: pool www'],
      serverConfig: 'Listen 80\nDocumentRoot "/opt/legacy/site"',
      docRoot: '/opt/legacy/site',
      fsHits: ['index.php', 'composer.json'],
    }
    const probeScript = phpSvc.buildProbeScript(['/opt/legacy/site'])
    check('probe script includes the DocumentRoot', probeScript.includes('/opt/legacy/site/index.php'))
    check('probe script still includes conventional roots', probeScript.includes('/var/www/html/index.php'))

    const report = await discovery.discover({ dockerClient: fakeClient({ containers: [c] }), skipHttpProbe: true })
    check('PHP found in the non-standard webroot', report.containers[0].php.isPhp === true, report.containers[0].php)
  }

  section('Apache with unreadable config degrades gracefully')
  {
    // Minimal image: no shell, exec denied — config comes back empty.
    const c = {
      id: 'ap-noconf',
      ps: ps({ id: 'ap-noconf', name: 'locked', image: 'httpd:2.4' }),
      inspect: inspect({
        id: 'ap-noconf', name: 'locked', image: 'httpd:2.4',
        exposed: exposedOnly(80),
        networks: { ln: { IPAddress: '172.45.0.2', Aliases: ['locked'] } },
      }),
      processes: ['1 root httpd -DFOREGROUND'],
      // no serverConfig and no fsHits -> execCapture returns {ok:false}
    }
    const report = await discovery.discover({ dockerClient: fakeClient({ containers: [c] }), skipHttpProbe: true })
    const ctr = report.containers[0]
    check('discovery did not throw', report.ok === true)
    check('Apache still detected from image + process', ctr.server.server === 'apache')
    check('still recognized as a web app', ctr.web.isWeb === true, ctr.web)
    check('serverConfig is empty rather than missing', ctr.serverConfig.empty === true, ctr.serverConfig)
  }

  section('Apache sticky ports and multi-app allocation')
  {
    const mk = (id, name, service, project) => ({
      id, name, composeService: service, composeProject: project,
      image: 'httpd:2.4',
      networks: [{ name: 'n1', ipAddress: '172.46.0.2' }],
      ports: [{ containerPort: 80, protocol: 'tcp', published: false, hostPort: null }],
      web: { port: 80, published: false, hostPort: null, networkAliases: ['n1'], reachability: 'docker-internal', isWeb: true },
      php: { isPhp: false, confidence: 0 }, runtime: { label: 'static (Apache)' },
    })
    const store = {}
    const db = { getState: k => store[k], setState: (k, v) => { store[k] = v } }
    const resolve = ctr => Promise.resolve({ target: `${ctr.composeService}:80`, basis: 'docker-network-alias', network: 'n1', attached: 'already' })

    const apacheApp = mk('s1', 'shop_apache', 'web', 'shop')
    const first = await routesSvc.planRoutes([apacheApp], { db, resolveUpstream: resolve })
    const port = first.routes[0].listenPort
    check('an Apache app gets a port', typeof port === 'number')

    const second = await routesSvc.planRoutes([apacheApp], { db, resolveUpstream: resolve })
    check('rerunning keeps the same port', second.routes[0].listenPort === port, { port, second: second.routes[0].listenPort })

    const other = mk('s2', 'blog_apache', 'blog', 'blog')
    const both = await routesSvc.planRoutes([apacheApp, other], { db, resolveUpstream: resolve })
    check('the first app keeps its port', both.routes[0].listenPort === port, both.routes.map(r => r.listenPort))
    check('a second Apache app gets a different port', both.routes[0].listenPort !== both.routes[1].listenPort, both.routes.map(r => r.listenPort))
  }

  section('A newly discovered app must not steal an existing app\'s port')
  {
    // Regression: adding Apache to a host already protecting an nginx app
    // moved nginx off :8080, purely because Docker listed Apache first.
    // Remembered ports are reserved before any new allocation.
    const mkApp = (name, service, project, image) => ({
      id: name, name, composeService: service, composeProject: project, image,
      networks: [{ name: 'nx', ipAddress: '172.48.0.2' }],
      ports: [{ containerPort: 80, protocol: 'tcp', published: false, hostPort: null }],
      web: { port: 80, published: false, hostPort: null, networkAliases: ['nx'], reachability: 'docker-internal', isWeb: true },
      php: { isPhp: false, confidence: 0 }, runtime: { label: 'x' },
    })
    const existingNginx = mkApp('shop_nginx', 'nginx', 'shop', 'nginx:1.25-alpine')
    const newApache = mkApp('blog_apache', 'apache', 'blog', 'httpd:2.4')

    // nginx already owns 8080 from a previous run.
    const store = { auto_route_ports: { 'shop/nginx': 8080 } }
    const db = { getState: k => store[k], setState: (k, v) => { store[k] = v } }
    const resolve = ctr => Promise.resolve({ target: `${ctr.composeService}:80`, basis: 'docker-network-alias', network: 'nx', attached: 'already' })

    // Apache is listed FIRST — the exact ordering that caused the bug.
    const { routes } = await routesSvc.planRoutes([newApache, existingNginx], { db, resolveUpstream: resolve })
    const byName = Object.fromEntries(routes.map(r => [r.containerName, r.listenPort]))
    check('the existing nginx app keeps :8080', byName.shop_nginx === 8080, byName)
    check('the new Apache app takes a different port', byName.blog_apache !== 8080, byName)
    check('both apps are routed', routes.length === 2, byName)
  }

  section('--dry-run does not persist port assignments')
  {
    const app = {
      id: 'dr1', name: 'dr_apache', composeService: 'web', composeProject: 'dr', image: 'httpd:2.4',
      networks: [{ name: 'dn', ipAddress: '172.49.0.2' }],
      ports: [{ containerPort: 80, protocol: 'tcp', published: false, hostPort: null }],
      web: { port: 80, published: false, hostPort: null, networkAliases: ['dn'], reachability: 'docker-internal', isWeb: true },
      php: { isPhp: false, confidence: 0 }, runtime: { label: 'x' },
    }
    const store = {}
    const db = { getState: k => store[k], setState: (k, v) => { store[k] = v } }
    const resolve = () => Promise.resolve({ target: 'web:80', basis: 'docker-network-alias', network: 'dn', attached: 'already' })

    await routesSvc.planRoutes([app], { db, resolveUpstream: resolve, persist: false })
    check('nothing was written to stored state', store[routesSvc.PORT_ASSIGNMENT_KEY] === undefined, store)

    await routesSvc.planRoutes([app], { db, resolveUpstream: resolve, persist: true })
    check('a real run does persist', !!store[routesSvc.PORT_ASSIGNMENT_KEY], store)
  }

  section('Apache published to the host still warns about the bypass')
  {
    const apacheApp = {
      id: 'pub-ap', name: 'pub_apache', composeService: 'web', image: 'httpd:2.4',
      networks: [{ name: 'n2', ipAddress: '172.47.0.2' }],
      ports: [{ containerPort: 80, protocol: 'tcp', published: true, hostPort: 9000 }],
      web: { port: 80, published: true, hostPort: 9000, networkAliases: ['n2'], reachability: 'host-published', isWeb: true },
      php: { isPhp: false, confidence: 0 }, runtime: { label: 'static (Apache)' },
    }
    const { routes } = await routesSvc.planRoutes([apacheApp], {
      resolveUpstream: () => Promise.resolve({ target: 'web:80', basis: 'docker-network-alias', network: 'n2', attached: 'already', bypassPath: 9000 }),
    })
    check('a route is still generated', routes.length === 1)
    check('the published origin port is flagged as a WAF bypass',
      routes[0].warnings.some(w => /bypass/i.test(w) && /9000/.test(w)), routes[0].warnings)
  }

  // ══════════════════════════════════════════════════════════════════
  // Untrusted input reaching generated configuration
  //
  // Everything discovery learns comes from a container: labels, env vars
  // and config files, all chosen by whoever built or ran it. Those values
  // reach a `sh -c` command (filesystem probes) and the Caddyfile CatWAF
  // writes, so each is checked at the boundary AND at the sink.
  // ══════════════════════════════════════════════════════════════════

  section('A hostile compose-service label cannot reach the config')
  {
    const hostile = 'evil\n    respond "PWNED" 200\n    #'
    const normalized = containersSvc.normalize(
      { ID: 'h1', Names: 'safe_container', Image: 'nginx:1.25-alpine' },
      {
        Id: 'h1', Name: '/safe_container',
        Config: {
          Image: 'nginx:1.25-alpine', Env: [], ExposedPorts: { '80/tcp': {} },
          Labels: { 'com.docker.compose.service': hostile, 'com.docker.compose.project': hostile },
        },
        State: { Running: true },
        NetworkSettings: { Ports: {}, Networks: { n: { IPAddress: '172.50.0.2' } } },
      })
    check('the label is rejected, not escaped', normalized.composeService === 'safe_container', normalized.composeService)
    check('no newline survives into composeService', !/[\r\n]/.test(normalized.composeService))
    check('a hostile compose project is dropped', normalized.composeProject === null, normalized.composeProject)

    check('plain service names still pass through',
      containersSvc.safeName('my-app_1.2') === 'my-app_1.2')
    check('names with spaces are rejected', containersSvc.safeName('my app', 'fb') === 'fb')
    check('over-long names are rejected', containersSvc.safeName('a'.repeat(200), 'fb') === 'fb')
  }

  section('The generator refuses anything it cannot vouch for')
  {
    const evil = 'evil\n    respond "PWNED" 200\n    #'
    let threw = false
    try { generatorSvc.buildRouteBlock({ listenPort: 8099, upstream: `${evil}:80` }, state.WAF) } catch { threw = true }
    check('an upstream containing a newline is refused', threw)

    threw = false
    try { generatorSvc.buildRouteBlock({ listenPort: '80 }\n:9999 {', upstream: 'ok:80' }, state.WAF) } catch { threw = true }
    check('a non-numeric listen port is refused', threw)

    check('a normal host:port upstream is accepted', generatorSvc.assertSafeUpstream('nginx:80') === 'nginx:80')
    check('an IPv4 upstream is accepted', generatorSvc.assertSafeUpstream('172.19.0.4:80') === '172.19.0.4:80')
    check('an IPv6 upstream is accepted', generatorSvc.assertSafeUpstream('[fd00::1]:8080') === '[fd00::1]:8080')

    // Free text only ever appears in comments, which must stay one line.
    const region = generatorSvc.buildAutoRegion([{
      name: evil, containerName: evil, listenPort: 8099, upstream: 'ok:80',
      runtime: 'PHP\n respond "PWNED2" 200', warnings: [],
    }], state.WAF)
    const escaped = region.split('\n').filter(l => /PWNED/.test(l) && !l.trimStart().startsWith('#'))
    check('no payload escapes a comment into a directive line', escaped.length === 0, escaped)
  }

  section('A hostile DocumentRoot cannot inject into the filesystem probe')
  {
    // The probe is a `sh -c` string run via `docker exec`, and command
    // substitution expands inside double quotes.
    for (const bad of ['/var/www/`id`', '/var/www/$(id)', '/var/www/${IFS}x', '/var/www/a b', '/etc/../../root']) {
      check(`rejected: ${bad}`, phpSvc.safeWebroots([bad]).length === 0)
    }
    check('a plain path is still used', phpSvc.safeWebroots(['/srv/app-1.2_x']).length === 1)

    const script = phpSvc.buildProbeScript(['/var/www/`id`', '/srv/ok'])
    check('no command substitution in the generated probe', !/[`$]/.test(script), script.slice(0, 120))
    check('the safe webroot is still probed', script.includes('/srv/ok/index.php'))

    const parsed = webserversSvc.parseServerConfig('DocumentRoot /var/www/`id`')
    check('the parser still surfaces it (sanitising is the probe\'s job)', parsed.documentRoots.length === 1)
    check('but it never reaches a shell', phpSvc.buildProbeScript(parsed.documentRoots).includes('`id`') === false)
  }

  section('A hostile PHP_VERSION env var cannot reach the config')
  {
    const info = phpSvc.detect(
      { image: 'x', env: { PHP_VERSION: '8.3\n    respond "PWNED" 200\n#' }, ports: [], networks: [] },
      { dockerClient: { execCapture: () => ({ ok: false, stdout: '' }) }, processes: ['php-fpm: master process'] })
    check('only the version number is kept', info.runtime === 'PHP 8.3', info.runtime)
    check('no newline in the runtime label', !/[\r\n]/.test(info.runtime))

    check('a hostile backend PHP_VERSION is also clamped',
      fastcgiSvc.backendPhpVersion({ env: { PHP_VERSION: '8.2\nrespond x' }, image: 'y' }) === '8.2')
  }

  // ── Probe robustness ────────────────────────────────────────────────

  section('A failed HTTP probe never erases stronger evidence')
  {
    // A published port that nothing answers on. The container is still
    // demonstrably a web server (nginx process + image), so the failed
    // probe must not demote it — the probe adds confidence, it never
    // subtracts it.
    const mk = (containerPort, hostPort) => ({
      id: 'p1',
      ps: ps({ id: 'p1', name: 'nginx_noanswer', image: 'nginx:1.25-alpine' }),
      inspect: inspect({
        id: 'p1', name: 'nginx_noanswer', image: 'nginx:1.25-alpine',
        labels: { 'com.docker.compose.service': 'web' },
        ports: published(containerPort, hostPort),
        networks: { appnet: { IPAddress: '172.24.0.2', Aliases: ['web'] } },
      }),
      processes: ['1 root nginx: master process', '7 nginx nginx: worker process'],
    })

    // 19599 / 19598 are dead ports — the probe will genuinely fail.
    const common = await discovery.discover({ dockerClient: fakeClient({ containers: [mk(80, 19599)] }), skipHttpProbe: false })
    const c1 = common.containers[0]
    check('probe actually failed', c1.web.httpCheck && c1.web.httpCheck.ok === false, c1.web.httpCheck)
    check('still detected as a web app (common port)', c1.web.isWeb === true, c1.web)
    check('failure is recorded as evidence, not a penalty',
      c1.web.evidence.some(e => /HTTP probe failed/.test(e)), c1.web.evidence)

    const uncommon = await discovery.discover({ dockerClient: fakeClient({ containers: [mk(7777, 19598)] }), skipHttpProbe: false })
    const c2 = uncommon.containers[0]
    check('still detected as a web app (uncommon port)', c2.web.isWeb === true, c2.web)

    // And the same container with a working probe must score higher.
    const live = http.createServer((q, s) => s.end('ok'))
    await new Promise(r => live.listen(19597, '127.0.0.1', r))
    const working = await discovery.discover({ dockerClient: fakeClient({ containers: [mk(80, 19597)] }), skipHttpProbe: false })
    check('a successful probe scores strictly higher than a failed one',
      working.containers[0].web.confidence > c1.web.confidence,
      { withProbe: working.containers[0].web.confidence, withoutProbe: c1.web.confidence })
    await new Promise(r => live.close(r))
  }

  section('Discovery is identical with and without HTTP probing')
  {
    // `auto` and `auto --dry-run` must never disagree about what exists.
    const c = {
      id: 'd1',
      ps: ps({ id: 'd1', name: 'freshmart_nginx', image: 'nginx:1.25-alpine' }),
      inspect: inspect({
        id: 'd1', name: 'freshmart_nginx', image: 'nginx:1.25-alpine',
        labels: { 'com.docker.compose.service': 'nginx' },
        ports: published(80, 19596),
        networks: { 'fake-web_freshmart': { IPAddress: '172.20.0.3', Aliases: ['nginx'] } },
      }),
      processes: ['1 root nginx: master process'],
    }
    const withProbe = await discovery.discover({ dockerClient: fakeClient({ containers: [c] }), skipHttpProbe: false })
    const without = await discovery.discover({ dockerClient: fakeClient({ containers: [c] }), skipHttpProbe: true })
    check('both find the same number of web apps', withProbe.webApps.length === without.webApps.length && withProbe.webApps.length === 1,
      { withProbe: withProbe.webApps.length, without: without.webApps.length })
    check('both pick the same port', withProbe.containers[0].web.port === without.containers[0].web.port)
  }

  // ── protect() result shape (the `auto` vs `auto --dry-run` bug) ──────

  section('An apply failure is reported as a failure, not as "nothing found"')
  {
    const protectSvc = require(path.join(ROOT, 'backend/services/proxy/protect.js'))
    const applyMod = require(path.join(ROOT, 'backend/services/proxy/apply.js'))
    const netMod = require(path.join(ROOT, 'backend/services/proxy/network.js'))

    const c = {
      id: 'ap1',
      ps: ps({ id: 'ap1', name: 'freshmart_nginx', image: 'nginx:1.25-alpine' }),
      inspect: inspect({
        id: 'ap1', name: 'freshmart_nginx', image: 'nginx:1.25-alpine',
        labels: { 'com.docker.compose.service': 'nginx' },
        ports: published(80, 19595),
        networks: { 'fake-web_freshmart': { IPAddress: '172.20.0.3', Aliases: ['nginx'] } },
      }),
      processes: ['1 root nginx: master process'],
    }
    const client = {
      ...fakeClient({ containers: [c] }),
      inspectNetwork: () => ({ Driver: 'bridge', Internal: false, Containers: {} }),
      networkConnect: () => ({ ok: true }),
    }

    const realApply = applyMod.apply
    const realDescribe = netMod.describeProxy
    netMod.describeProxy = () => ({ container: null, networks: [], inContainer: false, source: null })
    applyMod.apply = o => (o.dryRun ? realApply(o) : { ok: false, error: 'simulated write failure' })
    try {
      const res = await protectSvc.protect({ dockerClient: client, state, db: null, dryRun: false, skipHttpProbe: true })
      check('result reports failure', res.ok === false && res.stage === 'apply', res.stage)
      check('webApps is still present on the failure path', Array.isArray(res.webApps) && res.webApps.length === 1, res.webApps)
      check('containers still present', Array.isArray(res.containers) && res.containers.length === 1)
      check('the real error is carried', /simulated write failure/.test(res.error), res.error)

      // dry-run over the same environment must agree about what exists
      const dry = await protectSvc.protect({ dockerClient: client, state, db: null, dryRun: true, skipHttpProbe: true })
      check('dry-run finds the same web apps', dry.webApps.length === res.webApps.length, { dry: dry.webApps.length, wet: res.webApps.length })
    } finally {
      applyMod.apply = realApply
      netMod.describeProxy = realDescribe
    }
  }

  section('Configuration generation')
  {
    const routes = [{
      name: 'store', containerName: 'store', containerId: 'c1',
      listenPort: 8080, upstream: 'store:80', upstreamBasis: 'docker-network-alias',
      framework: 'Laravel', runtime: 'PHP 8.3', phpConfidence: 96, warnings: [],
    }]
    const region = generatorSvc.buildAutoRegion(routes, state.WAF)
    check('region contains start marker', region.includes(generatorSvc.AUTO_MARKER_START))
    check('region contains end marker', region.includes(generatorSvc.AUTO_MARKER_END))
    check('region contains the listen port', region.includes(':8080 {'))
    check('region reverse-proxies to the docker-network alias', region.includes('reverse_proxy store:80'))
    check('region embeds coraza_waf protection', region.includes('coraza_waf {'))

    check('no routes produces null (nothing to write)', generatorSvc.buildAutoRegion([], state.WAF) === null)
  }

  section('--dry-run makes no changes')
  {
    const before = fs.readFileSync(process.env.CADDYFILE_PATH, 'utf8')
    const routes = [{
      name: 'store', containerName: 'store', containerId: 'c1',
      listenPort: 8095, upstream: 'store:80', upstreamBasis: 'docker-network-alias',
      framework: null, runtime: 'PHP 8.3', phpConfidence: 90, warnings: [],
    }]
    const result = applySvc.apply({ routes, waf: state.WAF, dryRun: true })
    check('reports dryRun', result.dryRun === true)
    check('reports ok', result.ok === true)
    check('config was generated', typeof result.config === 'string' && result.config.includes(':8095'))
    const after = fs.readFileSync(process.env.CADDYFILE_PATH, 'utf8')
    check('Caddyfile untouched', before === after)
  }

  section('Configuration validation failure keeps previous config')
  {
    const before = fs.readFileSync(process.env.CADDYFILE_PATH, 'utf8')
    const originalValidate = configTx.validateCaddyfile
    configTx.validateCaddyfile = () => ({ ok: false, error: 'simulated validation failure' })
    try {
      const routes = [{
        name: 'broken', containerName: 'broken', containerId: 'c99',
        listenPort: 8096, upstream: 'broken:80', upstreamBasis: 'docker-network-alias',
        framework: null, runtime: null, phpConfidence: null, warnings: [],
      }]
      const result = applySvc.apply({ routes, waf: state.WAF, dryRun: false })
      check('apply reports failure', result.ok === false)
      check('error mentions validation', /validation failed/.test(result.error))
      const after = fs.readFileSync(process.env.CADDYFILE_PATH, 'utf8')
      check('Caddyfile left untouched after failed validation', before === after)
    } finally {
      configTx.validateCaddyfile = originalValidate
    }
  }

  if (HAVE_CADDY) {
    section('Real apply succeeds and is reversible (requires local `caddy` binary)')
    const before = fs.readFileSync(process.env.CADDYFILE_PATH, 'utf8')
    const routes = [{
      name: 'realapp', containerName: 'realapp', containerId: 'c100',
      listenPort: 8097, upstream: '127.0.0.1:9999', upstreamBasis: 'published-host-port',
      framework: null, runtime: 'PHP 8.3', phpConfidence: 80, warnings: ['test warning'],
    }]
    const result = applySvc.apply({ routes, waf: state.WAF, dryRun: false })
    check('apply succeeds against the real caddy binary', result.ok === true, result)
    check('a backup was recorded', typeof result.backup === 'string' && fs.existsSync(result.backup))
    const after = fs.readFileSync(process.env.CADDYFILE_PATH, 'utf8')
    check('new Caddyfile contains the route', after.includes(':8097'))
    check('backup contains the pre-apply content', fs.readFileSync(result.backup, 'utf8') === before)
  } else {
    console.log(c_skip('(skipping real-apply test — `caddy` binary not on PATH)'))
  }

  console.log(`\n${pass} passed, ${fail} failed\n`)
  process.exit(fail ? 1 : 0)
})()

function c_skip(msg) { return '  skip ' + msg }
