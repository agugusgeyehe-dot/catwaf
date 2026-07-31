#!/usr/bin/env node

const path = require('path')
const { spawn } = require('child_process')

const PROJECT_ROOT = path.join(__dirname, '..')
require(path.join(PROJECT_ROOT, 'backend', 'services', 'env.js')).load()

spawn(process.execPath, ['scripts/ensure-catai-runtime.js'], { cwd: PROJECT_ROOT, stdio: 'inherit', detached: true }).unref()

const hasDomain = !!process.env.DOMAIN

if (!hasDomain) {
  spawn(process.execPath, ['backend/server.js'], { cwd: PROJECT_ROOT, stdio: 'inherit' })
    .on('exit', (code) => process.exit(code ?? 0))
} else {
  const concurrentlyBin = path.join(PROJECT_ROOT, 'node_modules', '.bin', 'concurrently')
  const caddyfile = process.env.CADDYFILE_PATH || path.join(PROJECT_ROOT, 'Caddyfile')
  spawn(concurrentlyBin, [
    '-k', '-n', 'backend,caddy', '-c', 'blue,green',
    'node backend/server.js',
    `caddy run --config ${caddyfile} --adapter caddyfile`,
  ], { cwd: PROJECT_ROOT, stdio: 'inherit' })
    .on('exit', (code) => process.exit(code ?? 0))
}
