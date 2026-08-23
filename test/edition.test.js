
const assert = require('assert')
const fs = require('fs')
const os = require('os')
const path = require('path')
const { spawnSync } = require('child_process')

const ROOT = path.join(__dirname, '..')
const CLI = path.join(ROOT, 'bin', 'catwaf.js')
const SETUP_SH = path.join(ROOT, 'setup.sh')

let passed = 0, failed = 0
function section(name) { console.log(`\n== ${name} ==`) }
function check(label, cond, detail) {
  if (cond) { console.log(`  ok   ${label}`); passed++ }
  else { console.log(`  FAIL ${label}`, detail !== undefined ? JSON.stringify(detail) : ''); failed++ }
}

function cli(args, env = {}) {
  const tmpEnv = path.join(os.tmpdir(), `catwaf-test-env-${process.pid}`)
  if (!fs.existsSync(tmpEnv)) fs.writeFileSync(tmpEnv, '', { mode: 0o600 })
  const r = spawnSync(process.execPath, [CLI, ...args], {
    cwd: ROOT,
    encoding: 'utf8',
    timeout: 60000,
    env: { ...process.env, CATWAF_ENV_FILE: tmpEnv, NO_COLOR: '1', ...env },
  })
  return { code: r.status, out: (r.stdout || '') + (r.stderr || '') }
}

function sh(args, env = {}) {
  const r = spawnSync('bash', [SETUP_SH, ...args], {
    cwd: ROOT, encoding: 'utf8', timeout: 30000,
    env: { ...process.env, NO_COLOR: '1', ...env },
  })
  return { code: r.status, out: (r.stdout || '') + (r.stderr || '') }
}

section('edition service')
{
  const editionPath = require.resolve(path.join(ROOT, 'backend', 'services', 'edition.js'))
  function freshEdition(value) {
    delete require.cache[editionPath]
    if (value === undefined) delete process.env.CATWAF_EDITION
    else process.env.CATWAF_EDITION = value
    return require(editionPath)
  }

  const lite = freshEdition('lite')
  check('CATWAF_EDITION=lite resolves to lite', lite.current() === 'lite')
  check('isLite() true, isFull() false', lite.isLite() === true && lite.isFull() === false)
  check('explicit value is reported as explicit', lite.isExplicit() === true)

  const full = freshEdition('full')
  check('CATWAF_EDITION=full resolves to full', full.current() === 'full')

  const upper = freshEdition('LITE')
  check('edition value is case-insensitive', upper.current() === 'lite')

  const junk = freshEdition('enterprise-plus')
  check('unrecognised edition falls back, not crashes', ['lite', 'full'].includes(junk.current()))
  check('unrecognised edition is not reported as explicit', junk.isExplicit() === false)

  const inferred = freshEdition(undefined)
  check('unset edition is inferred from what is on disk', ['lite', 'full'].includes(inferred.current()))
  check('inferred edition is not reported as explicit', inferred.isExplicit() === false)

  check('isValid accepts lite/full only',
    full.isValid('lite') && full.isValid('full') && !full.isValid('') && !full.isValid('pro'))

  const l = freshEdition('lite')
  const blocked = l.checkCapability('docker')
  check('docker is blocked in Lite', blocked !== null && blocked.code === 'EDITION_LITE')
  check('refusal names the fix', /catwaf setup --full/.test(blocked.message))
  check('refusal promises data preservation', /preserved/i.test(blocked.message))
  check('commands with no capability entry are never blocked', l.checkCapability('audit') === null)

  const f = freshEdition('full')
  check('docker is allowed in Full', f.checkCapability('docker') === null)

  delete process.env.CATWAF_EDITION
}

section('CLI: version and edition reporting')
{
  const pkg = require(path.join(ROOT, 'package.json'))
  const v = cli(['version'])
  check('`catwaf version` exits 0', v.code === 0, v)
  // Asserted as a shape rather than a literal. A hardcoded version here has to
  // be hand-edited every release and fails the whole suite when someone forgets,
  // which teaches people to edit the test rather than check the claim. The
  // claim worth checking is that the CLI prints a bare semver and that it is
  // the same one the package manifests declare — the next two checks.
  check('`catwaf version` prints a bare semver', /^\d+\.\d+\.\d+$/.test(v.out.trim()), v.out.trim())
  check('CLI version matches package.json', v.out.trim() === pkg.version, v.out.trim())

  const frontendPkg = require(path.join(ROOT, 'frontend', 'package.json'))
  check('frontend package.json version matches', frontendPkg.version === pkg.version, frontendPkg.version)

  const e = cli(['edition'], { CATWAF_EDITION: 'lite' })
  check('`catwaf edition` reports lite', e.out.trim() === 'lite', e.out.trim())
  const e2 = cli(['edition'], { CATWAF_EDITION: 'full' })
  check('`catwaf edition` reports full', e2.out.trim() === 'full', e2.out.trim())
}

section('CLI: help covers exactly what dispatches')
{
  const help = cli(['help'])
  check('`catwaf help` exits 0', help.code === 0)

  const src = fs.readFileSync(CLI, 'utf8')
  const NAME = "[a-z0-9][a-z0-9-]*"
  const dispatched = new Set([...src.matchAll(new RegExp(`case '(${NAME})':`, 'g'))].map(m => m[1]))
  const mainHelp = src.slice(src.indexOf('main: `'), src.indexOf('setup: `'))
  const advertised = new Set(
    [...mainHelp.matchAll(new RegExp(`^ {2}(${NAME})(?: [<[][^\\]>]*[\\]>])?\\s{2,}\\S`, 'gm'))].map(m => m[1])
  )

  // Consecutive bare cases fall through to one handler ("case 'user': case
  // 'users': …"), and help documents the first spelling rather than every
  // one. Everything after the first in such a run is an alias — detect that
  // instead of keeping a list that has to be edited whenever one is added.
  const aliases = new Set()
  for (const run of src.matchAll(new RegExp(`(?:case '${NAME}':\\s*){2,}`, 'g'))) {
    const names = [...run[0].matchAll(new RegExp(`case '(${NAME})':`, 'g'))].map(m => m[1])
    for (const name of names.slice(1)) aliases.add(name)
  }

  const undocumented = [...dispatched].filter(c => !advertised.has(c) && !aliases.has(c))
  check('every dispatchable command appears in help', undocumented.length === 0, undocumented)
  check('the alias detector still finds the long-standing aliases',
    aliases.has('install') && aliases.has('users'), [...aliases])
  check('a command with its own handler is never treated as an alias',
    !aliases.has('setup') && !aliases.has('doctor') && !aliases.has('settings'), [...aliases])

  const nonexistent = [...advertised].filter(c => !dispatched.has(c))
  check('help advertises no command that does not dispatch', nonexistent.length === 0, nonexistent)

  for (const cmd of ['setup', 'docker', 'audit', 'explain', 'rules', 'health']) {
    const h = cli(['help', cmd])
    check(`\`catwaf help ${cmd}\` prints a topic`, h.code === 0 && h.out.length > 80, h.out.length)
  }
}

section('CLI: exit codes')
{
  check('unknown command exits 2 (usage)', cli(['definitely-not-a-command']).code === 2)
  check('help exits 0', cli(['help']).code === 0)
  check('version exits 0', cli(['version']).code === 0)
  check('no arguments exits 0 with help', cli([]).code === 0)
}

section('CLI: edition gating is real')
{
  const liteDocker = cli(['docker', 'up'], { CATWAF_EDITION: 'lite' })
  check('docker in Lite exits 5 (wrong edition)', liteDocker.code === 5, liteDocker.code)
  check('docker in Lite explains the fix', /catwaf setup --full/.test(liteDocker.out), liteDocker.out.slice(0, 120))
  check('docker in Lite shows no stack trace', !/at \w+ \(/.test(liteDocker.out) && !/Error:/.test(liteDocker.out))
  check('docker in Lite does not pretend to succeed', !/started|running|up-to-date/i.test(liteDocker.out))

  const liteHelp = cli(['help', 'audit'], { CATWAF_EDITION: 'lite' })
  check('non-Full-only commands still work in Lite', liteHelp.code === 0)
}

section('CLI: docker subcommand allowlist')
{
  const docker = require(path.join(ROOT, 'src', 'tui', 'docker.js'))
  const expected = ['up', 'down', 'restart', 'status', 'ps', 'logs', 'build']
  check('every documented subcommand exists',
    expected.every(s => s in docker.SUBCOMMANDS), Object.keys(docker.SUBCOMMANDS))
  check('no undocumented subcommands',
    Object.keys(docker.SUBCOMMANDS).every(s => expected.includes(s)))

  for (const [name, spec] of Object.entries(docker.SUBCOMMANDS)) {
    check(`${name} expands to a constant argument array`,
      Array.isArray(spec.args) && spec.args.every(a => typeof a === 'string' && a.length > 0))
  }

  const src = fs.readFileSync(path.join(ROOT, 'src', 'tui', 'docker.js'), 'utf8')
  check('docker wrapper never uses a shell', !/shell:\s*true/.test(src))
  check('docker wrapper never uses exec()', !/\bexec\(|execSync\(/.test(src))

  const bad = cli(['docker', 'exec --privileged'], { CATWAF_EDITION: 'full' })
  check('injection-shaped subcommand is rejected', bad.code === 2, bad.code)
  check('rejection names the valid set', /Valid subcommands/.test(bad.out))

  const traversal = cli(['docker', '../../../bin/sh'], { CATWAF_EDITION: 'full' })
  check('path-traversal subcommand is rejected', traversal.code === 2, traversal.code)

  const none = cli(['docker'], { CATWAF_EDITION: 'full' })
  check('missing subcommand exits 2 and prints usage', none.code === 2 && /Usage/.test(none.out))
}

section('GeoIP: never fabricates a location')
{
  const geoip = require(path.join(ROOT, 'backend', 'services', 'geoip.js'))

  const privates = [
    '10.0.0.1', '192.168.1.1', '172.16.0.1', '172.31.255.255', '127.0.0.1',
    '169.254.1.1', '100.64.0.1', '0.0.0.0', '198.18.0.1', '224.0.0.1',
    '::1', 'fe80::1', 'fc00::1', 'fd12:3456::1',
  ]
  for (const ip of privates) {
    check(`${ip} is private`, geoip.isPrivateIp(ip) === true)
    check(`${ip} yields no coordinates`, geoip.lookup(ip) === null)
  }

  check('::ffff:10.0.0.1 is recognised as private', geoip.isPrivateIp('::ffff:10.0.0.1') === true)
  check('::ffff:10.0.0.1 yields no coordinates', geoip.lookup('::ffff:10.0.0.1') === null)
  check('::ffff:192.168.0.5 is recognised as private', geoip.isPrivateIp('::ffff:192.168.0.5') === true)

  const malformed = ['', null, undefined, 'not-an-ip', '999.999.999.999', '1.2.3', '../../etc/passwd',
    "1.2.3.4'; DROP TABLE request_log;--", '1.2.3.4\n5.6.7.8', {}, [], 12345]
  for (const bad of malformed) {
    check(`malformed input ${JSON.stringify(bad)} yields null`, geoip.lookup(bad) === null)
  }

  check('199.18.0.1 is not treated as private', geoip.isPrivateIp('199.18.0.1') === false)

  const pub = geoip.lookup('8.8.8.8')
  if (pub === null) {
    check('public IP without database data returns null (no fabrication)', true)
  } else {
    check('public IP returns in-range latitude', pub.lat >= -90 && pub.lat <= 90, pub.lat)
    check('public IP returns in-range longitude', pub.lon >= -180 && pub.lon <= 180, pub.lon)
    check('public IP returns a country code', typeof pub.country_code === 'string' && pub.country_code.length > 0)
    check('coordinates are finite numbers', Number.isFinite(pub.lat) && Number.isFinite(pub.lon))
  }

  check('lookup never throws on hostile input', (() => {
    for (const bad of [Symbol.iterator ? '\x00' : '', '‮', 'a'.repeat(10000)]) {
      try { geoip.lookup(bad) } catch { return false }
    }
    return true
  })())

  const avail = geoip.available()
  check('availability is reportable', typeof avail.ok === 'boolean')
}

section('GeoIP: attack-map clustering handles real rows only')
{
  const src = fs.readFileSync(path.join(ROOT, 'backend', 'services', 'requestLog.js'), 'utf8')
  check('attack-map query excludes rows without coordinates',
    /lat IS NOT NULL AND lon IS NOT NULL/.test(src))
  check('attack-map query is limited', /LIMIT \?/.test(src))
}

section('edition-aware installation')
{
  const pkg = require(path.join(ROOT, 'package.json'))
  check('postinstall no longer installs frontend unconditionally',
    !/npm --prefix frontend install/.test(pkg.scripts.postinstall), pkg.scripts.postinstall)
  check('postinstall delegates to the edition-aware script',
    /scripts\/postinstall\.js/.test(pkg.scripts.postinstall))
  check('postinstall script exists', fs.existsSync(path.join(ROOT, 'scripts', 'postinstall.js')))

  const post = fs.readFileSync(path.join(ROOT, 'scripts', 'postinstall.js'), 'utf8')
  check('postinstall reads CATWAF_EDITION', /CATWAF_EDITION/.test(post))
  check('postinstall skips frontend deps for lite', /edition === 'lite'/.test(post))
  check('postinstall never uses a shell', !/shell:\s*true/.test(post))

  const setup = require(path.join(ROOT, 'src', 'tui', 'setup.js'))
  check('EDITIONS exposes lite and full', 'lite' in setup.EDITIONS && 'full' in setup.EDITIONS)
  check('lite installs no dashboard', setup.EDITIONS.lite.dashboard === false)
  check('lite runs no API server', setup.EDITIONS.lite.api === false)
  check('lite installs no CatAI', setup.EDITIONS.lite.catai === false)
  check('full installs the dashboard', setup.EDITIONS.full.dashboard === true)
  check('full runs the API server', setup.EDITIONS.full.api === true)

  check('--lite maps to lite', setup.editionFromFlags({ lite: true }).edition === 'lite')
  check('--full maps to full', setup.editionFromFlags({ full: true }).edition === 'full')
  check('--minimal is accepted as lite', setup.editionFromFlags({ minimal: true }).edition === 'lite')
  check('--standard is accepted as full', setup.editionFromFlags({ standard: true }).edition === 'full')
  check('legacy flags are reported as legacy', setup.editionFromFlags({ minimal: true }).legacy === 'minimal')
  check('--lite with --full is an error', !!setup.editionFromFlags({ lite: true, full: true }).error)
  check('no flag means no edition chosen', setup.editionFromFlags({}).edition === null)
}

section('Lite start does not launch the API server')
{
  const cliSrc = fs.readFileSync(CLI, 'utf8')
  check('start branches on edition', /isLite\(\)/.test(cliSrc))
  const svc = require(path.join(ROOT, 'src', 'tui', 'service.js'))
  check('service exposes a WAF-only start', typeof svc.startWaf === 'function')
  check('service exposes WAF status', typeof svc.wafStatus === 'function')
}

section('setup.sh')
{
  check('setup.sh exists at the repository root', fs.existsSync(SETUP_SH))
  check('setup.sh is executable', (fs.statSync(SETUP_SH).mode & 0o111) !== 0)

  const src = fs.readFileSync(SETUP_SH, 'utf8')
  check('uses set -euo pipefail', /set -euo pipefail/.test(src))
  check('uses umask for secret writes', /umask 077/.test(src))
  check('installs a cleanup trap', /trap cleanup EXIT/.test(src))
  const codeLines = src.split('\n').filter(l => !/^\s*#/.test(l)).join('\n')
  check('never uses eval', !/(^|[;&|(]|\s)eval\s/.test(codeLines))
  check('does not pipe a downloaded script into a shell', !/curl[^\n|]*\|\s*(ba)?sh/.test(src))
  check('pins TLS for downloads', /--proto '=https'/.test(src) && /--tlsv1\.2/.test(src))
  check('writes .env mode 600', /chmod 600/.test(src))
  check('creates a non-root service account', /useradd --system|adduser -S/.test(src))
  check('systemd unit sets NoNewPrivileges', /NoNewPrivileges=true/.test(src))
  check('systemd unit does not run as root', /User=\$SERVICE_USER/.test(src))
  check('refuses to overwrite a foreign directory', /Refusing to overwrite/.test(src))

  const syntax = spawnSync('bash', ['-n', SETUP_SH], { encoding: 'utf8' })
  check('setup.sh parses without syntax errors', syntax.status === 0, syntax.stderr)

  check('--help exits 0', sh(['--help']).code === 0)

  const cases = [
    [['--lite', '--domain', 'bad;domain', '--yes'], /Invalid domain/, 'shell metacharacters in --domain'],
    [['--lite', '--domain', 'a b.com', '--yes'], /Invalid domain/, 'whitespace in --domain'],
    [['--lite', '--admin-user', 'a$(id)', '--yes'], /Invalid admin username/, 'command substitution in --admin-user'],
    [['--lite', '--admin-user', 'x', '--yes'], /Invalid admin username/, 'too-short --admin-user'],
    [['--lite', '--dir', 'relative', '--yes'], /absolute path/, 'relative --dir'],
    [['--lite', '--dir', '/opt/../etc', '--yes'], /\.\./, 'traversal in --dir'],
    [['--lite', '--full'], /not both/, 'contradictory editions'],
    [['--bogus'], /Unknown option/, 'unknown option'],
    [['--dir'], /requires a value/, 'trailing flag with no value'],
    [['--domain', '--yes'], /requires a value/, 'flag mistaken for a value'],
    [['--lite', '--with-ai'], /requires --full/, 'AI requested for Lite'],
  ]
  for (const [args, pattern, label] of cases) {
    const r = sh(args)
    check(`rejects ${label}`, r.code !== 0 && pattern.test(r.out), r.out.slice(0, 120))
  }

  const short = sh(['--lite', '--yes'], { CATWAF_ADMIN_PASSWORD: 'short' })
  check('rejects a too-short CATWAF_ADMIN_PASSWORD',
    short.code !== 0 && /at least 8/.test(short.out), short.out.slice(0, 120))

  // This case proves validation ACCEPTS a good argument set, using the
  // "must run as root" check as the sentinel that execution got that far.
  // As root that sentinel does not fire and the installer simply proceeds —
  // so running the suite under sudo really did execute setup.sh against
  // --dir /opt/catwaf, creating directories on the live system. A test must
  // never install anything. There is no sentinel to observe as root, so skip.
  if (typeof process.getuid === 'function' && process.getuid() === 0) {
    console.log('  SKIP  running as root — this case would execute the installer instead of stopping at the root check.')
  } else {
    const valid = sh(['--full', '--dir', '/opt/catwaf', '--domain', 'example.com', '--admin-user', 'admin'])
    check('a valid argument set passes validation', /must run as root/.test(valid.out), valid.out.slice(0, 120))
  }
}

section('no credentials or tokens in query strings')
{
  const auth = fs.readFileSync(path.join(ROOT, 'backend', 'middleware', 'auth.js'), 'utf8')
  check('softAuth no longer accepts ?token=', !/req\.query\?\.token|req\.query\.token/.test(auth))

  const api = fs.readFileSync(path.join(ROOT, 'frontend', 'src', 'utils', 'api.js'), 'utf8')
  check('frontend sends no token in a URL', !/token=\$\{/.test(api))
  check('dead EventSource helper is gone', !/streamEvents/.test(api))

  const signing = fs.readFileSync(path.join(ROOT, 'backend', 'middleware', 'signing.js'), 'utf8')
  check('no signature exemption for a nonexistent route', !/traffic\/stream/.test(signing))
}

section('frontend preference handling is validated')
{
  const prefs = fs.readFileSync(path.join(ROOT, 'frontend', 'src', 'utils', 'preferences.jsx'), 'utf8')
  check('preferences validate against an allowlist', /const ALLOWED = \{/.test(prefs))
  check('custom accent is checked as a hex colour', /HEX_COLOR/.test(prefs))
  check('localStorage access is guarded', /function safeGet|function safeSet/.test(prefs))
  check('sanitize is applied before writing the CSS variable',
    /setProperty\('--cat-accent-custom', sanitize/.test(prefs))
}

console.log(`\n${passed} passed, ${failed} failed\n`)
process.exit(failed === 0 ? 0 : 1)
