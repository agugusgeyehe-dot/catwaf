
const path = require('path')
const fs = require('fs')
const { spawn, spawnSync } = require('child_process')

const PROJECT_ROOT = path.join(__dirname, '..', '..')
const COMPOSE_FILE = path.join(PROJECT_ROOT, 'docker-compose.yml')

const EXIT = {
  OK: 0,
  FAILURE: 1,
  USAGE: 2,
  MISSING_DEPENDENCY: 3,
}

const SUBCOMMANDS = {
  up:      { args: ['up', '-d'],            desc: 'Build if needed and start the stack in the background' },
  down:    { args: ['down'],                desc: 'Stop the stack and remove its containers' },
  restart: { args: ['restart'],             desc: 'Restart every service in the stack' },
  status:  { args: ['ps'],                  desc: 'Show each service and its state' },
  ps:      { args: ['ps'],                  desc: 'Alias of `status`' },
  logs:    { args: ['logs', '--tail', '200'], desc: 'Show recent logs (--follow to stream)' },
  build:   { args: ['build'],               desc: 'Rebuild the stack images' },
}

function usage() {
  const rows = Object.entries(SUBCOMMANDS)
    .map(([name, { desc }]) => `  catwaf docker ${name.padEnd(8)} ${desc}`)
    .join('\n')
  return `Usage: catwaf docker <${Object.keys(SUBCOMMANDS).join('|')}>\n\n${rows}\n`
}

function resolveCompose() {
  const probe = spawnSync('docker', ['compose', 'version'], { stdio: 'ignore', timeout: 10000 })
  if (probe.status === 0) return { cmd: 'docker', prefix: ['compose'] }

  const legacy = spawnSync('docker-compose', ['version'], { stdio: 'ignore', timeout: 10000 })
  if (legacy.status === 0) return { cmd: 'docker-compose', prefix: [] }

  const dockerPresent = spawnSync('docker', ['--version'], { stdio: 'ignore', timeout: 10000 })
  return {
    error: dockerPresent.status === 0
      ? 'Docker is installed but the Compose plugin is not. Install it: https://docs.docker.com/compose/install/'
      : 'Docker is not installed or not on PATH. Install Docker: https://docs.docker.com/engine/install/',
  }
}

async function run(argv = [], flags = {}) {
  const sub = String(argv[0] || '').toLowerCase()

  if (!sub || sub === 'help' || flags.help) {
    console.log(usage())
    return sub ? EXIT.OK : EXIT.USAGE
  }

  if (!Object.prototype.hasOwnProperty.call(SUBCOMMANDS, sub)) {
    console.error(`Unknown docker subcommand: "${sub}"`)
    console.error(`Valid subcommands: ${Object.keys(SUBCOMMANDS).join(', ')}`)
    return EXIT.USAGE
  }

  if (!fs.existsSync(COMPOSE_FILE)) {
    console.error(`No docker-compose.yml found at ${COMPOSE_FILE}`)
    return EXIT.MISSING_DEPENDENCY
  }

  const compose = resolveCompose()
  if (compose.error) {
    console.error(compose.error)
    return EXIT.MISSING_DEPENDENCY
  }

  const args = [...compose.prefix, '-f', COMPOSE_FILE, ...SUBCOMMANDS[sub].args]
  if (sub === 'logs' && (flags.follow || flags.f)) args.push('--follow')
  if (sub === 'up' && flags.build) args.push('--build')

  const child = spawn(compose.cmd, args, { cwd: PROJECT_ROOT, stdio: 'inherit', shell: false })

  return await new Promise(resolve => {
    child.on('error', (e) => {
      console.error(`Could not run ${compose.cmd}: ${e.message}`)
      resolve(EXIT.MISSING_DEPENDENCY)
    })
    child.on('exit', (code, signal) => {
      if (signal) return resolve(EXIT.FAILURE)
      resolve(code === 0 ? EXIT.OK : EXIT.FAILURE)
    })
  })
}

module.exports = { run, usage, SUBCOMMANDS, EXIT }
