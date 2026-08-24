
const os = require('os')
const path = require('path')
const bcrypt = require('bcryptjs')

const WORKER_PATH = path.join(__dirname, 'passwordHash.worker.js')
const POOL_SIZE = Math.max(1, Math.min(2, (os.cpus()?.length || 1) - 1))
const TASK_TIMEOUT_MS = 15000
// bcryptjs runs synchronously inside the workers, so queued tasks are not
// merely waiting — they are guaranteed CPU the moment a worker frees up.
// Without this cap a flood of login attempts queues unboundedly and every
// subsequent real login (including the operator's) times out. Overflow is
// rejected fast instead of accepted and stalled.
const MAX_PENDING_TASKS = 64

let pool = null
let nextWorker = 0
let seq = 0
const pending = new Map()

function spawnPool() {
  if (pool) return pool
  let Worker
  try { ({ Worker } = require('worker_threads')) } catch { return null }

  const workers = []
  for (let i = 0; i < POOL_SIZE; i++) {
    let w
    try { w = new Worker(WORKER_PATH) } catch { return null }

    w.on('message', ({ id, value, error }) => {
      const task = pending.get(id)
      if (!task) return
      pending.delete(id)
      clearTimeout(task.timer)
      error ? task.reject(new Error(error)) : task.resolve(value)
    })
    const onDead = () => {
      for (const [id, task] of pending) {
        if (task.worker !== w) continue
        pending.delete(id)
        clearTimeout(task.timer)
        task.reject(new Error('password worker exited'))
      }
      pool = null
    }
    w.on('error', onDead)
    w.on('exit', onDead)
    w.unref()
    workers.push(w)
  }
  pool = workers
  return pool
}

function run(message) {
  const workers = spawnPool()
  if (!workers || workers.length === 0) {
    return Promise.resolve(
      message.op === 'hash'
        ? bcrypt.hashSync(message.password, message.cost)
        : bcrypt.compareSync(message.password, message.hash)
    )
  }

  if (pending.size >= MAX_PENDING_TASKS) {
    return Promise.reject(new Error('password queue full'))
  }

  const worker = workers[nextWorker++ % workers.length]
  const id = ++seq

  return new Promise((resolve, reject) => {
    const timer = setTimeout(() => {
      pending.delete(id)
      reject(new Error('password hashing timed out'))
    }, TASK_TIMEOUT_MS)
    timer.unref?.()
    pending.set(id, { resolve, reject, timer, worker })
    worker.postMessage({ id, ...message })
  })
}

const asString = v => (typeof v === 'string' ? v : '')

function compare(password, hash) {
  if (typeof hash !== 'string' || hash.length === 0) return Promise.resolve(false)
  return run({ op: 'compare', password: asString(password), hash })
}

function hash(password, cost) {
  return run({ op: 'hash', password: asString(password), cost })
}

module.exports = { compare, hash, POOL_SIZE }
