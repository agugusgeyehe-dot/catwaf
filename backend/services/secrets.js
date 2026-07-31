
const crypto = require('crypto')

let ROOT_SECRET = process.env.JWT_SECRET
let EPHEMERAL = false
if (!ROOT_SECRET || ROOT_SECRET.length < 32) {
  if (ROOT_SECRET) {
    console.warn('[CatWAF] JWT_SECRET is shorter than 32 characters — ignoring it and generating a strong one for this run.')
  }
  ROOT_SECRET = crypto.randomBytes(32).toString('hex')
  EPHEMERAL = true
  console.warn('[CatWAF] JWT_SECRET is not set — generated a random secret for this run.')
  console.warn('[CatWAF] Run `catwaf --setup` (or set JWT_SECRET in .env) before deploying;')
  console.warn('[CatWAF] otherwise every restart invalidates existing sessions.')
}

function derive(label, input = '') {
  return crypto.createHmac('sha256', ROOT_SECRET).update(`catwaf/v1/${label}/${input}`).digest('hex')
}

module.exports = {
  JWT_SECRET: ROOT_SECRET,
  isEphemeral: () => EPHEMERAL,
  derive,

  pathSecret: () => derive('path-root'),

  sessionKey: (jti) => derive('session-sig', jti),
}
