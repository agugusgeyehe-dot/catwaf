const express = require('express')
const router = express.Router()

const auditSvc = require('../services/audit')
const {
  authRequired, writeRequired,
  listUsers, addUser, removeUser, setPassword, setRole, findUser, verifyPassword,
  VALID_ROLES, MIN_PASSWORD_LENGTH,
} = require('../middleware/auth')

function bad(res, detail, code = 400) {
  return res.status(code).json({ detail })
}

router.get('/api/users', authRequired, writeRequired, (req, res) => {
  res.json({ users: listUsers(), roles: VALID_ROLES, min_password_length: MIN_PASSWORD_LENGTH })
})

router.post('/api/users', authRequired, writeRequired, (req, res) => {
  const { username, password, role } = req.body || {}
  if (typeof username !== 'string' || !/^[a-zA-Z0-9._-]{2,32}$/.test(username)) {
    return bad(res, 'Username must be 2-32 characters, letters/numbers/dot/underscore/hyphen only.')
  }
  if (typeof password !== 'string') return bad(res, 'Password is required.')
  try {
    const user = addUser({ username, password, role: role || 'viewer' })
    auditSvc.audit(req, 'user.add', username, { role: user.role })
    res.status(201).json({ user: { id: user.id, username: user.username, role: user.role, created_at: user.created_at } })
  } catch (e) {
    bad(res, e.message)
  }
})

router.post('/api/users/:username/password', authRequired, (req, res) => {
  const target = req.params.username
  const { password, current_password } = req.body || {}
  const isSelf = req.user.username === target

  if (!isSelf && req.user.role !== 'admin') {
    return bad(res, 'Only an admin can change another account\'s password.', 403)
  }
  if (!findUser(target)) return bad(res, 'User not found.', 404)
  if (typeof password !== 'string') return bad(res, 'password is required.')

  if (isSelf) {
    if (typeof current_password !== 'string' || !verifyPassword(target, current_password)) {
      return bad(res, 'Current password is incorrect.', 403)
    }
  }

  try {
    setPassword(target, password)
    auditSvc.audit(req, 'user.password', target, { self: isSelf })
    res.json({ message: 'Password updated.' })
  } catch (e) {
    bad(res, e.message)
  }
})

router.post('/api/users/:username/role', authRequired, writeRequired, (req, res) => {
  const target = req.params.username
  const { role } = req.body || {}
  if (!findUser(target)) return bad(res, 'User not found.', 404)
  try {
    const result = setRole(target, role)
    auditSvc.audit(req, 'user.role', target, { role: result.role })
    res.json(result)
  } catch (e) {
    bad(res, e.message)
  }
})

router.delete('/api/users/:username', authRequired, writeRequired, (req, res) => {
  const target = req.params.username
  if (target === req.user.username) return bad(res, 'You cannot delete the account you are logged in as.')
  if (!findUser(target)) return bad(res, 'User not found.', 404)
  try {
    removeUser(target)
    auditSvc.audit(req, 'user.remove', target, {})
    res.json({ message: `User "${target}" removed.` })
  } catch (e) {
    bad(res, e.message)
  }
})

module.exports = router
