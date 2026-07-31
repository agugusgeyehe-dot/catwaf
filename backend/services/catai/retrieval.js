
const fs = require('fs')
const path = require('path')
const yaml = require('js-yaml')

const KNOWLEDGE_DIR = path.join(__dirname, '..', '..', 'knowledge')

const FIELD_WEIGHT = { questions: 4, keywords: 3, title: 3, body: 1 }
const BIGRAM_BONUS = 2

const MIN_SCORE = 0.55
const MIN_COVERAGE = 0.34

const STOPWORDS = new Set(`a about all also am an and any are as at be been but by can cant come could
did do does doesnt doing dont for from get got had has have how i if in into is it its just me my no
not of on or our out own she so some than that the their them then there these they this those to too
up us use used using very was way we were what when where which who why will with would you your yours
please help need want know tell show make made does do`.split(/\s+/))

const MIN_STEM_LEN = 4

function stem(w) {
  if (w.length <= 3) return w
  if (w.endsWith('ing') && w.length - 3 >= MIN_STEM_LEN) return w.slice(0, -3)
  if (w.endsWith('ed') && w.length - 2 >= MIN_STEM_LEN) return w.slice(0, -2)
  if (w.endsWith('es') && w.length - 2 >= MIN_STEM_LEN) return w.slice(0, -2)
  if (w.endsWith('s') && !w.endsWith('ss') && w.length - 1 >= MIN_STEM_LEN) return w.slice(0, -1)
  return w
}

const IP_SHAPE_RE = /\b\d{1,3}(?:\.\d{1,3}){3}(?:\/\d{1,2})?\b/g

function tokenize(text, { keepStopwords = false } = {}) {
  return String(text || '')
    .toLowerCase()
    .replace(IP_SHAPE_RE, ' ipaddr ')
    .replace(/[^a-z0-9\s]/g, ' ')
    .split(/\s+/)
    .filter(Boolean)
    .filter(w => !/^\d+$/.test(w))
    .filter(w => keepStopwords || !STOPWORDS.has(w))
    .map(stem)
}

let INDEX = null

function parseDoc(file, raw) {
  const m = /^---\n([\s\S]*?)\n---\n([\s\S]*)$/.exec(raw)
  if (!m) throw new Error(`${file}: missing frontmatter`)
  const fm = yaml.load(m[1]) || {}
  const body = m[2].trim()
  for (const required of ['id', 'title', 'keywords', 'questions']) {
    if (!fm[required]) throw new Error(`${file}: frontmatter missing "${required}"`)
  }

  const termWeight = new Map()
  const addField = (text, weight) => {
    for (const t of tokenize(text)) {
      if ((termWeight.get(t) || 0) < weight) termWeight.set(t, weight)
    }
  }
  addField(fm.title, FIELD_WEIGHT.title)
  addField((fm.keywords || []).join(' '), FIELD_WEIGHT.keywords)
  addField((fm.questions || []).join(' '), FIELD_WEIGHT.questions)
  addField(body, FIELD_WEIGHT.body)

  const bigrams = new Set()
  for (const text of [fm.title, ...(fm.keywords || []), ...(fm.questions || [])]) {
    const toks = tokenize(text, { keepStopwords: true })
    for (let i = 0; i < toks.length - 1; i++) bigrams.add(toks[i] + ' ' + toks[i + 1])
  }

  return {
    id: fm.id,
    file,
    title: fm.title,
    keywords: fm.keywords || [],
    questions: fm.questions || [],
    related: fm.related || [],
    actions: fm.actions || [],
    body,
    termWeight,
    bigrams,
  }
}

function buildIndex() {
  const docs = []
  for (const file of fs.readdirSync(KNOWLEDGE_DIR).filter(f => f.endsWith('.md')).sort()) {
    docs.push(parseDoc(file, fs.readFileSync(path.join(KNOWLEDGE_DIR, file), 'utf8')))
  }
  if (!docs.length) throw new Error('knowledge base is empty')

  const df = new Map()
  for (const d of docs) for (const t of d.termWeight.keys()) df.set(t, (df.get(t) || 0) + 1)
  const idf = new Map()
  for (const [t, n] of df) idf.set(t, Math.log(1 + docs.length / n))

  INDEX = { docs, idf, loadedAt: new Date().toISOString() }
  return INDEX
}

function getIndex() { return INDEX || buildIndex() }

const META_QUESTION_DOC = 'catai-assistant'
const META_QUESTIONS = [
  'what can you do', 'what do you do', 'who are you', 'what are you',
  'help', 'what is this', 'are you an ai', 'are you ai',
]
function metaQuestionOverride(query) {
  const norm = String(query).toLowerCase().trim().replace(/[^a-z0-9\s]/g, '').replace(/\s+/g, ' ')
  return META_QUESTIONS.includes(norm) ? META_QUESTION_DOC : null
}

function scoreDoc(doc, queryTerms, queryBigrams, idf) {
  let score = 0
  const matched = []
  for (const t of queryTerms) {
    const w = doc.termWeight.get(t)
    if (!w) continue
    score += (idf.get(t) || 1) * w
    matched.push(t)
  }
  for (const bg of queryBigrams) if (doc.bigrams.has(bg)) score += BIGRAM_BONUS
  return { score, matched }
}

function search(query, { limit = 2 } = {}) {
  const { docs, idf } = getIndex()
  const queryTerms = [...new Set(tokenize(query))]
  const rawToks = tokenize(query, { keepStopwords: true })
  const queryBigrams = []
  for (let i = 0; i < rawToks.length - 1; i++) queryBigrams.push(rawToks[i] + ' ' + rawToks[i + 1])

  const metaId = metaQuestionOverride(query)
  if (metaId) {
    const doc = docs.find(d => d.id === metaId)
    if (doc) return { confident: true, docs: [doc], coverage: 1, topScore: MIN_SCORE, breakdown: [{ id: metaId, score: MIN_SCORE, matched: ['(meta-question override)'] }] }
  }

  if (!queryTerms.length) {
    return { confident: false, docs: [], coverage: 0, topScore: 0, breakdown: [] }
  }

  const norm = Math.sqrt(queryTerms.length)
  const scored = docs
    .map(d => {
      const { score, matched } = scoreDoc(d, queryTerms, queryBigrams, idf)
      return { doc: d, score: score / norm, matched }
    })
    .sort((a, b) => b.score - a.score)

  const top = scored[0]
  const coverage = top ? top.matched.length / queryTerms.length : 0
  const confident = !!top && top.score >= MIN_SCORE && coverage >= MIN_COVERAGE

  return {
    confident,
    coverage,
    topScore: top ? top.score : 0,
    docs: confident ? scored.slice(0, limit).filter(s => s.score > 0).map(s => s.doc) : [],
    breakdown: scored.slice(0, 5).map(s => ({ id: s.doc.id, score: +s.score.toFixed(3), matched: s.matched })),
  }
}

function truncateOnHeading(body, maxChars) {
  if (body.length <= maxChars) return body
  const cut = body.slice(0, maxChars)
  const lastHeading = cut.lastIndexOf('\n## ')
  return (lastHeading > maxChars * 0.4 ? cut.slice(0, lastHeading) : cut).trimEnd() + '\n…'
}

function buildDocsBlock(docs, { maxChars = 5600 } = {}) {
  if (!docs.length) return ''
  const per = Math.floor(maxChars / docs.length)
  return docs.map(d => `### ${d.title}\n${truncateOnHeading(d.body, per)}`).join('\n\n')
}

function allTitles() { return getIndex().docs.map(d => ({ id: d.id, title: d.title })) }
function getDoc(id) { return getIndex().docs.find(d => d.id === id) || null }

module.exports = {
  search, buildDocsBlock, allTitles, getDoc, getIndex, buildIndex,
  tokenize, stem, truncateOnHeading,
  KNOWLEDGE_DIR, MIN_SCORE, MIN_COVERAGE,
}
