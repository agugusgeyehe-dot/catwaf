#!/usr/bin/env node

const path = require('path')
const { spawn } = require('child_process')

const PROJECT_ROOT = path.join(__dirname, '..')
require(path.join(PROJECT_ROOT, 'backend', 'services', 'env.js')).load()

spawn(process.execPath, ['scripts/ensure-catai-runtime.js'], { cwd: PROJECT_ROOT, stdio: 'inherit', detached: true }).unref()

const hasDomain = !!process.env.DOMAIN

if (!hasDomain) {
  spawn(process.execPath, ['backend/server.js'], { cwd: PROJECT_ROOT, stdio: 'inherit', execArgv: ['--experimental-sqlite'] })
    .on('exit', (code) => process.exit(code ?? 0))
} else {
  // Both processes are spawned with argv arrays — never through a shell.
  // This used to hand `caddy run --config ${CADDYFILE_PATH}` to concurrently,
  // which runs each command string through a shell; anyone who could write
  // .env (where CADDYFILE_PATH lives) could therefore run arbitrary commands
  // as the service user at next start. Spawning argv arrays directly keeps
  // the platform test's no-shell-subprocess invariant true along this path.
  const caddyfile = process.env.CADDYFILE_PATH || path.join(PROJECT_ROOT, 'Caddyfile')
  const caddyBin = process.env.CADDY_BINARY || 'caddy'

  const children = [
    // execArgv is how the sqlite flag reaches the actual backend process —
    // flags on the supervisor's own command line do not propagate through
    // child_process.spawn.
    spawn(process.execPath, ['backend/server.js'], { cwd: PROJECT_ROOT, stdio: 'inherit', execArgv: ['--experimental-sqlite'] }),
    spawn(caddyBin, ['run', '--config', caddyfile, '--adapter', 'caddyfile'], { cwd: PROJECT_ROOT, stdio: 'inherit' }),
  ]

  let stopping = false
  const stop = (errChild) => {
    if (stopping) return
    stopping = true
    for (const other of children) {
      if (other !== errChild && !other.killed && other.exitCode === null) other.kill('SIGTERM')
    }
  }
  for (const child of children) {
    child.on('exit', (code) => {
      if (stopping) return
      stop(child)
      process.exit(code ?? 0)
    })
    // A failed spawn emits 'error' without a guaranteed 'exit'; without
    // this handler the supervisor would crash and orphan its surviving
    // sibling.
    child.on('error', () => {
      stop(child)
      process.exit(1)
    })
  }

  for (const sig of ['SIGTERM', 'SIGINT']) {
    process.on(sig, () => {
      if (stopping) return
      stopping = true
      for (const child of children) if (!child.killed) child.kill(sig)
      setTimeout(() => process.exit(0), 3000).unref()
    })
  }
}
