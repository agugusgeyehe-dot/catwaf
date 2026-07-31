
const crypto = require('crypto')
const db = require('../db')

const MAX_ENTRIES = 20
const DB_KEY = 'catai_undo'

let ring = load()

function load() {
  const stored = db.getState(DB_KEY)
  return Array.isArray(stored) ? stored.slice(-MAX_ENTRIES) : []
}

function persist() {
  try { db.setState(DB_KEY, ring) } catch {}
}

function record({ actionId, params, prev, user }) {
  const id = crypto.randomBytes(8).toString('hex')
  ring.push({ id, actionId, params, prev, user, ts: new Date().toISOString(), undone: false })
  if (ring.length > MAX_ENTRIES) ring = ring.slice(-MAX_ENTRIES)
  persist()
  return id
}

function find(id) { return ring.find(e => e.id === id) || null }

function markUndone(id) {
  const entry = find(id)
  if (entry) { entry.undone = true; persist() }
}

function recent(n = 10) {
  return ring.slice(-n).reverse().map(({ id, actionId, params, user, ts, undone }) => ({ id, actionId, params, user, ts, undone }))
}

module.exports = { record, find, markUndone, recent }
