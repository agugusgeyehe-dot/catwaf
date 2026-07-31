const { parentPort } = require('worker_threads')
const bcrypt = require('bcryptjs')

parentPort.on('message', ({ id, op, password, hash, cost }) => {
  try {
    const value = op === 'hash'
      ? bcrypt.hashSync(password, cost)
      : bcrypt.compareSync(password, hash)
    parentPort.postMessage({ id, value })
  } catch (e) {
    parentPort.postMessage({ id, error: e.message })
  }
})
