
const express = require('express')
const router = express.Router()
const { asyncHandler } = require('../middleware/errorHandler')
const securityScoreSvc = require('../services/securityScore')

router.get('/api/security/score', asyncHandler(async (req, res) => {
  const result = await securityScoreSvc.getSecurityScore()
  res.json(result)
}))

module.exports = router
