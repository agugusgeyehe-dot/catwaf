
const requestLog = require('./requestLog')

function recentTraffic(n = 50) {
  return requestLog.getRecent(n).map(toLegacyShape)
}

function toLegacyShape(row) {
  return {
    id: row.id,
    timestamp: row.ts,
    ip: row.ip,
    method: row.method,
    uri: row.uri,
    status: row.status,
    score: row.score,
    action: row.action,
    attack_type: row.attack_type,
    rule_ids: row.rule_ids,
    country: row.country_code || null,
    city: row.city || null,
    bytes: null,
    duration_ms: null,
  }
}

module.exports = { recentTraffic }
