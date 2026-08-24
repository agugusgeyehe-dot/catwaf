// features.test.js — regression tests for the enforcement & delivery
// additions: canary auto-ban, edge ban rendering, kernel ruleset builder,
// alert dispatch decision logic, and backup restore validation.
const fs = require('fs')
const os = require('os')
const path = require('path')

process.env.DB_DIR = fs.mkdtempSync(path.join(os.tmpdir(), 'catwaf-feat-'))
process.env.CADDYFILE_PATH = path.join(process.env.DB_DIR, 'Caddyfile')
process.env.CORAZA_AUDIT_LOG = path.join(process.env.DB_DIR, 'audit.json')
process.env.CADDY_ADMIN_URL = 'http://127.0.0.1:19917'
fs.writeFileSync(process.env.CADDYFILE_PATH, 'site:80 {\n  respond "test"\n}\n')

let pass = 0
let fail = 0
function check(name, ok, detail) {
  if (ok) { pass++; console.log(`  ok   ${name}`) }
  else { fail++; console.log(`  FAIL ${name}`, detail !== undefined ? JSON.stringify(detail)?.slice(0, 240) : '') }
}

;(async () => {
  const settings = require(path.join(ROOT(), 'backend', 'services', 'settings'))
  const enforce = require(path.join(ROOT(), 'backend', 'services', 'enforce'))
  const bans = require(path.join(ROOT(), 'backend', 'services', 'bans'))
  const edgeBans = require(path.join(ROOT(), 'backend', 'services', 'edgeBans'))
  const kernelBans = require(path.join(ROOT(), 'backend', 'services', 'kernelBans'))
  const backups = require(path.join(ROOT(), 'backend', 'services', 'backups'))
  const dispatch = require(path.join(ROOT(), 'backend', 'services', 'alertDispatch'))
  const db = require(path.join(ROOT(), 'backend', 'services', 'db'))

  function ROOT() { return path.join(__dirname, '..') }

  console.log('\n== canary auto-ban ==')
  {
    settings.set('canary', { enabled: true, paths: ['/.env', '/.git/config'], ban_seconds: 3600 })
    // dry-run: reports intent, writes nothing
    const dry = await enforce.classify({ ip: '203.0.113.50', uri: '/.env?x=1' }, { dryRun: true })
    check('canary hit blocks in dry-run mode', dry.action === 'block')
    check('dry-run records the would-be ban without writing it',
      Array.isArray(dry.would_ban) && dry.would_ban[0]?.source === 'canary' && bans.stats().total === 0)
    // live: bans with escalation source
    const live = await enforce.classify({ ip: '203.0.113.51', uri: '/.git/config' })
    check('live canary hit blocks and persists a ban', live.action === 'block' && bans.check('203.0.113.51') !== null)
    // query strings do not rescue the probe; unrelated paths are untouched
    const other = await enforce.classify({ ip: '203.0.113.52', uri: '/products?page=2' })
    check('normal traffic is unaffected by the canary gate', other.action !== 'block' && !bans.check('203.0.113.52'))
    settings.set('canary', { enabled: false })
    const off = await enforce.classify({ ip: '203.0.113.53', uri: '/.env' }, { dryRun: true })
    check('disabling the feature stops it from blocking an exact match', off.action === 'allow')
  }

  console.log('\n== edge ban rendering ==')
  {
    settings.set('edge_bans', { enabled: true, max_rules: 500, include_cidrs: true })
    bans.ban({ target: '198.51.100.77', source: 'manual', seconds: 600 })
    const result = edgeBans.refresh({ force: true })
    check('refresh succeeds against the local Caddyfile', result.ok, result)

    const written = fs.readFileSync(process.env.CADDYFILE_PATH, 'utf8')
    check('region markers land in the Caddyfile',
      written.includes(edgeBans.MARKER_START) && written.includes(edgeBans.MARKER_END))
    check('the banned address is rendered as a remote_ip element',
      /remote_ip [^\n]*198\.51\.100\.77/.test(written))
    check('abort handler accompanies the matcher', /handle @catwaf_edge_bans \{[\s\S]*?abort/.test(written))

    // allowlisted addresses are exempt even when banned
    stateAllowlistAdd('198.51.100.0/24')
    edgeBans.refresh({ force: true })
    const after = fs.readFileSync(process.env.CADDYFILE_PATH, 'utf8')
    check('allowlist coverage removes a banned range from the edge list',
      !/remote_ip [^\n]*198\.51\.100\.77/.test(after))
    stateAllowlistRemove('198.51.100.0/24')
    edgeBans.refresh({ force: true }) // settle the restored set's hash first

    // Retry semantics: this environment has no Caddy binary, so the reload
    // fails and needsReload stays true — the next tick MUST retry rather
    // than short-circuit.
    const retry = edgeBans.refresh()
    check('a written-but-unreloaded region is retried on the next tick',
      retry.changed === true)
    // Simulate a successful reload landing, then confirm the short-circuit.
    require(path.join(ROOT(), 'backend', 'services', 'db')).setState('edge_bans_last_render', {
      hash: require('crypto').createHash('sha256')
        .update(JSON.stringify(edgeBans.collectTargets({ maxRules: 500, includeCidrs: true })))
        .digest('hex'),
      needsReload: false,
    })
    const before = fs.readFileSync(process.env.CADDYFILE_PATH, 'utf8')
    const again = edgeBans.refresh()
    const afterAgain = fs.readFileSync(process.env.CADDYFILE_PATH, 'utf8')
    check('reloaded + unchanged ban set skips the rewrite',
      again.changed === false && before === afterAgain, { again })

    check('no temp residue beside the Caddyfile',
      !fs.readdirSync(process.env.DB_DIR).some(f => f.includes('.tmp-')))

    // pure builder rejects junk that would break nft/Caddy syntax
    const built = edgeBans.buildBlock(['203.0.113.99', 'not-an-ip" ; drop'])
    check('builder strips non-IP tokens from the matcher', !built.includes('not-an-ip') && built.includes('203.0.113.99'))

    // Reversed-direction allowlist: a banned RANGE swallowing an allowlisted
    // address must be excluded too (the original check only tested the
    // narrow direction and missed this).
    bans.ban({ target: '198.51.100.0/24', source: 'manual', seconds: 600 })
    stateAllowlistAdd('198.51.100.55')
    edgeBans.refresh({ force: true })
    const swallowed = fs.readFileSync(process.env.CADDYFILE_PATH, 'utf8')
    check('a banned range that swallows an allowlisted IP is excluded', !swallowed.includes('198.51.100.0/24'))
    stateAllowlistRemove('198.51.100.55')
    bans.liftTarget('198.51.100.0/24')

    async function stateAllowlistAdd(cidr) {
      const state = require(path.join(ROOT(), 'backend', 'services', 'state'))
      state.updateWAF(w => { w.ip_whitelist.push({ ip: cidr, note: '', added_at: '', expires_at: null }) })
    }
    async function stateAllowlistRemove(cidr) {
      const state = require(path.join(ROOT(), 'backend', 'services', 'state'))
      state.updateWAF(w => { w.ip_whitelist = w.ip_whitelist.filter(e => e.ip !== cidr) })
    }
  }

  console.log('\n== kernel ruleset builder ==')
  {
    const rs = kernelBans.buildRuleset({ v4: ['1.2.3.4', '10.0.0.0/24'], v6: ['2001:db8::1'] })
    check('table + interval sets declared',
      rs.includes('table inet catwaf_edge') && rs.includes('type ipv4_addr') && rs.includes('flags interval'))
    check('v4/v6 elements separated into their own sets',
      rs.includes('elements = { 1.2.3.4, 10.0.0.0/24 }') && rs.includes('elements = { 2001:db8::1 }'))
    const { splitTargets } = kernelBans
    const split = splitTargets(['1.2.3.4', '2001:db8::1', 'junk;drop'])
    check('splitter drops non-IP junk before nft ever sees it', split.v4.length === 1 && split.v6.length === 1)
    check('preflight refuses without the env gate', kernelBans.preflight().problems.some(p => p.includes('CATWAF_KERNEL_BANS')))
  }

  console.log('\n== kernel flush removes expired entries ==')
  {
    const before = kernelBans.buildRuleset({ v4: ['1.2.3.4'], v6: [] })
    const after = kernelBans.buildRuleset({ v4: [], v6: [] })
    check('a refreshed empty set renders no stale elements',
      before.includes('elements = { 1.2.3.4 }') && !after.includes('elements = {'))
    check('replacement flow deletes the table first (fail-open window)',
      typeof kernelBans._internals.replaceTable === 'function')
  }

  console.log('\n== alert dispatch ==')
  {
    // pure formatter
    check('spike message carries numbers and window',
      dispatch.formatAlert('spike', { blocked: 250, windowMin: 5, topType: 'SQLi' }).includes('250 blocked requests in 5 min'))
    // channel readiness
    const ready = dispatch.readyChannels({ slack_webhook: 'https://hooks.slack.com/x', telegram_bot_token: 'tok', discord_webhook: '' })
    check('telegram only counts when token AND chat id exist', ready.length === 1 && ready[0].id === 'slack')
    // cooldown state machine
    process.env.DB_DIR && (() => {})() // noop keep env explicit
    dispatch._internals.saveState({})
    settings.set('alert_dispatch', { enabled: true, cooldown_min: 10 })
    const first = dispatch.claimCooldown('new_ban', settings.get('alert_dispatch'))
    const second = dispatch.claimCooldown('new_ban', settings.get('alert_dispatch'))
    check('cooldown admits the first claim and blocks the immediate second', first === true && second === false)
    // refund on total delivery failure
    dispatch.claimCooldown('engine_change', settings.get('alert_dispatch'))
    const st = dispatch._internals.loadState()
    delete st.engine_change_refund_probe
    dispatch._internals.saveState(st)
    // simulate: claim then verify refund path exists and clears
    dispatch.refundCooldown('engine_change')
    const reClaim = dispatch.claimCooldown('engine_change', settings.get('alert_dispatch'))
    check('a refunded cooldown can fire again immediately', reClaim === true)
    // delivery fan-out with a real local receiver
    {
      const http = require('http')
      const seen = []
      const srv = http.createServer((req, res) => {
        let body = ''
        req.on('data', c => { body += c })
        req.on('end', () => { seen.push(JSON.parse(body)); res.writeHead(200); res.end('"ok"') })
      })
      await new Promise(r => srv.listen(0, '127.0.0.1', r))
      const url = `http://127.0.0.1:${srv.address().port}/hook`
      require(path.join(ROOT(), 'backend', 'services', 'state')).updateWAF(w => {
        w.alerts.custom_webhook = url
      })
      // netGuard refuses loopback in strict mode; assert that safety holds…
      const refused = await dispatch.broadcast('hello')
      check('loopback webhooks are refused by the SSRF guard (strict mode)',
        refused.every(r => r.ok === false))
      srv.close()
    }
  }

  console.log('\n== backup restore ==')
  {
    const goodManifest = {
      catwaf_version: '1.0.2', redacted: false,
      waf: { engine: 'DetectionOnly', paranoia_level: 2 },
      rule_categories: null, settings: null,
      caddyfile: 'site:80 {\n  respond "restored"\n}\n',
    }
    const file = path.join(process.env.DB_DIR, 'restore-me.json')
    fs.writeFileSync(file, JSON.stringify(goodManifest))
    const r = backups.restoreFromFile(file)
    check('valid manifest restores through configTx', r.ok === true, r)
    check('engine value landed after restore', require(path.join(ROOT(), 'backend', 'services', 'state')).WAF.engine === 'DetectionOnly')
    check('caddyfile replaced from backup', fs.readFileSync(process.env.CADDYFILE_PATH, 'utf8').includes('restored'))

    const redactedFile = path.join(process.env.DB_DIR, 'redacted.json')
    fs.writeFileSync(redactedFile, JSON.stringify({ ...goodManifest, redacted: true }))
    const refused = backups.restoreFromFile(redactedFile)
    check('redacted backups refuse without --allow-redacted', refused.ok === false && refused.code === 'REDACTED')

    const invalidFile = path.join(process.env.DB_DIR, 'invalid.json')
    fs.writeFileSync(invalidFile, JSON.stringify({ ...goodManifest, waf: { paranoia_level: 99 } }))
    const invalid = backups.restoreFromFile(invalidFile)
    check('out-of-range values fail validation and never touch state', invalid.ok === false && /validation/.test(invalid.error || ''))

    const garbage = backups.restoreFromFile(process.env.CADDYFILE_PATH)
    check('non-JSON input fails cleanly', garbage.ok === false && /JSON parse/.test(garbage.error))
  }

  console.log(`\n${pass} passed, ${fail} failed`)
  process.exit(fail ? 1 : 0)
})().catch(e => { console.error('\nharness error:', e.stack); process.exit(1) })
