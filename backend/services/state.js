
const db = require('./db')

const DEFAULT_WAF = {
  engine: 'On',
  paranoia_level: 1,
  executing_paranoia_level: 2,
  inbound_anomaly_threshold: 5,
  outbound_anomaly_threshold: 4,
  allowed_methods: ['GET','POST','HEAD','OPTIONS'],
  allowed_content_types: [
    'application/x-www-form-urlencoded','multipart/form-data','text/xml',
    'application/xml','application/json',
  ],
  max_request_body_size: 13107200,
  max_file_upload_size: 1048576,
  request_body_inspection: true,
  response_body_inspection: false,
  audit_log: true,
  audit_log_parts: ['A','B','E','F','H'],
  enforce_bodyproc_urlencoded: false,
  early_blocking: true,
  sampling_percentage: 100,
  geo_blocking: [],
  ip_whitelist: [],
  ip_blacklist: [],
  custom_rules: [],
  rule_exclusions: [],
  disabled_rules: [],
  php_exclusions: { wordpress: false, drupal: false, joomla: false, laravel: false, symfony: false },
  rate_limit: { enabled: false, requests_per_min: 120, burst: 20, per: 'ip' },
  retention_days: 30,
  alerts: { slack_webhook: '', email_to: '', custom_webhook: '', spike_threshold: 100 },
  blocked_user_agents: ['sqlmap','nikto','nmap','masscan','zgrab','dirbuster','gobuster','wfuzz','hydra','burpsuite'],
  header_rules: [],
}

const DEFAULT_RULE_CATEGORIES = {
  '920': { name: 'Protocol Enforcement', enabled: true, count: 47 },
  '921': { name: 'Protocol Attack', enabled: true, count: 11 },
  '930': { name: 'Local File Inclusion', enabled: true, count: 18 },
  '931': { name: 'Remote File Inclusion', enabled: true, count: 7 },
  '932': { name: 'Remote Command Execution', enabled: true, count: 58 },
  '933': { name: 'PHP Injection', enabled: true, count: 37 },
  '934': { name: 'Node.js Injection', enabled: true, count: 4 },
  '941': { name: 'XSS (Cross-Site Scripting)', enabled: true, count: 62 },
  '942': { name: 'SQL Injection', enabled: true, count: 108 },
  '943': { name: 'Session Fixation', enabled: true, count: 6 },
  '944': { name: 'Java Attack', enabled: true, count: 7 },
  '949': { name: 'Blocking Evaluation', enabled: true, count: 2 },
  '980': { name: 'Anomaly Scoring', enabled: true, count: 2 },
}

function loadWAF() { return { ...DEFAULT_WAF, ...(db.getState('waf') || {}) } }
function loadRuleCategories() { return db.getState('rule_categories') || { ...DEFAULT_RULE_CATEGORIES } }

const state = {
  WAF: loadWAF(),
  RULE_CATEGORIES: loadRuleCategories(),

  DEFAULT_WAF, DEFAULT_RULE_CATEGORIES,

  // Everything added after the original flat WAF blob lives in its own
  // validated, per-group namespace (services/settings). Exposed here so
  // renderers and the transaction pipeline reach all configuration through
  // one object, and so a group participates in snapshot/rollback for free.
  settings: require('./settings'),

  saveWAF(skipCaddy = false) {
    db.setState('waf', state.WAF)
    if (!skipCaddy) {
      setImmediate(() => {
        try {
          const caddy = require('./caddy')
          if (typeof caddy.applyToCaddy === 'function') caddy.applyToCaddy('waf.autosave', null)
        } catch (e) { console.error('[CatWAF] Auto Caddy reload failed:', e.message) }
      })
    }
  },
  saveRuleCategories() { db.setState('rule_categories', state.RULE_CATEGORIES) },

  reloadAllFromDb() {
    Object.assign(state.WAF, loadWAF())
    Object.assign(state.RULE_CATEGORIES, loadRuleCategories())
    state.settings.reloadAllFromDb()
  },
}

module.exports = state
