export const SEVERITY_META = {
  emergency: { label: 'Critical', rank: 0, color: '#f25c5c' },
  alert:     { label: 'Critical', rank: 0, color: '#f25c5c' },
  critical:  { label: 'Critical', rank: 0, color: '#f25c5c' },
  error:     { label: 'High',     rank: 1, color: '#f59e0b' },
  warning:   { label: 'Medium',   rank: 2, color: '#eab308' },
  notice:    { label: 'Low',      rank: 3, color: '#7c8db0' },
  info:      { label: 'Low',      rank: 3, color: '#7c8db0' },
  debug:     { label: 'Low',      rank: 3, color: '#7c8db0' },
}

export function severityMeta(sev) {
  return SEVERITY_META[sev] || { label: 'Unknown', rank: 4, color: '#5c6577' }
}
