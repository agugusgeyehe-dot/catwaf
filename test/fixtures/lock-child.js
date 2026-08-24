// Child worker for concurrency tests. Runs against a DB_DIR given by argv,
// performs `count` updateWAF mutations appending unique entries, exits 0.
const process = require('process')
const path = require('path')

const [, , mode, dbDir, tag, countRaw] = process.argv
const count = Number(countRaw || '10')

// Env must be set BEFORE backend services load.
process.env.DB_DIR = dbDir

const ROOT = path.join(__dirname, '..', '..')
const state = require(path.join(ROOT, 'backend', 'services', 'state'))
const configLock = require(path.join(ROOT, 'backend', 'services', 'configLock'))

async function main() {
  if (mode === 'waf') {
    // Each child pushes `count` uniquely-tagged blacklist entries through
    // the cross-process-safe mutation path. Lost updates would drop some.
    for (let i = 0; i < count; i++) {
      state.updateWAF(w => {
        const fs2 = require('fs')
        const trace = `${dbDir}/trace.log`
        const t0 = Date.now()
        const info = configLock._internal.lockInfo()
        const sawRev = Number(require('/home/zachary/catwaf-free-release/backend/services/db.js').getState('waf__rev'))
        w.ip_blacklist.push({ ip: `10.${tag}.${i}.1`, note: String(tag), added_at: '', expires_at: null })
        fs2.appendFileSync(trace, `${t0} tag=${tag} i=${i} sawRev=${sawRev} countAfter=${w.ip_blacklist.length}\n`)
      }, { label: `test.waf.${tag}` })
    }
    const total = state.WAF.ip_blacklist.filter(e => e.note === String(tag)).length
    if (total !== count) {
      console.error(`child ${tag}: only ${total}/${count} of its own entries visible at exit`)
      process.exit(2)
    }
    process.exit(0)
  }

  if (mode === 'lockfile') {
    // Each acquisition appends one line to a shared log while holding the
    // config lock. Interleaved writes would tear or lose lines.
    const fs = require('fs')
    const logPath = `${dbDir}/shared.log`
    for (let i = 0; i < count; i++) {
      configLock.withConfigLock(() => {
        const current = fs.existsSync(logPath) ? fs.readFileSync(logPath, 'utf8') : ''
        // Simulate real work between read and write so a broken lock shows
        // up as lost lines rather than mere reordering.
        let x = 0; for (let j = 0; j < 20000; j++) x += Math.sqrt(j)
        if (!Number.isFinite(x)) throw new Error('unreachable')
        fs.writeFileSync(logPath, `${current}${tag}:${i}\n`)
      })
    }
    process.exit(0)
  }

  console.error(`unknown mode ${mode}`)
  process.exit(3)
}

main().catch(e => { console.error(e.stack); process.exit(1) })
