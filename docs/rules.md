# Rules and tuning

How CatWAF Free decides what to block, and what to change when it gets it wrong.

## Paranoia levels and anomaly scoring

Coraza and the OWASP CRS work on an **anomaly-scoring** model, not pass/fail per rule. Each matched rule adds points, and a request is blocked once the total crosses a threshold. Two settings control this:

**Paranoia level (1–4)** — how suspicious the rule set is.

| Level | What it catches | False-positive risk |
|---|---|---|
| **1** | Clear attacks: SQL injection, XSS, command injection, path traversal | Very low — the default, and right for most sites |
| **2** | Adds patterns that are usually malicious but occasionally appear in real input | Low, but worth watching |
| **3** | Adds aggressive heuristics | Noticeable — expect to tune |
| **4** | Nearly everything unusual | High — assume you'll be writing exceptions |

Raise one level at a time and watch for legitimate visitors being blocked. If they are, drop back down; a firewall that blocks your customers is worse than one set slightly loose.

**Anomaly threshold** — the score a request must reach before it's blocked, tunable separately for inbound and outbound traffic. Lower is stricter.

```
GET/POST  /api/waf/paranoia
GET/POST  /api/waf/anomaly
```

Or use the dashboard: **Paranoia Levels** in the sidebar. Or just ask CatAI: *"set paranoia to 2"*.

## Engine mode

The master switch, at `GET/POST /api/waf/engine`:

| Mode | Behaviour |
|---|---|
| `On` | Attacks are blocked. |
| `DetectionOnly` | Attacks are logged but allowed through. |
| `Off` | No inspection at all. |

`DetectionOnly` is the safe way to trial a stricter paranoia level: turn it on, raise the level, watch what *would* have been blocked, then commit.

## When legitimate visitors get blocked

In rough order of how targeted the fix is — prefer the narrowest one that works:

1. **Allowlist the affected IP** (`/ip/whitelist`, or `POST /api/ip/add`). Immediate, and the right emergency fix when a real customer is stuck. Entries can expire automatically; prefer that to permanent ones, since an allowlisted address bypasses every rule.
2. **Add CMS compatibility exclusions** if the problem is a WordPress, Drupal, Joomla, Laravel, or Symfony admin area. These relax the specific rules known to fire on those platforms' own traffic, rather than weakening anything globally. CatAI can add these for you (it will ask first — it's a reduction in coverage).
3. **Lower the paranoia level** by one. Blunt, but honest: if level 3 is blocking real users on your site, level 3 is wrong for your site.

## Performance

`GET/POST /api/performance-mode` trades inspection depth for throughput — worth touching only if the WAF is measurably slowing you down. The main lever is **sampling**: inspecting a percentage of traffic rather than all of it. That is a real reduction in coverage, so the page tells you what each setting costs.

## Custom rules

CatWAF writes real Coraza `SecRule` directives into your Caddyfile between marker comments. Custom rules follow the same path — there's no separate WAF config to hand-edit.

The most direct way to add one is to ask CatAI:

```
"block any request whose path contains /xmlrpc.php"
```

which produces:

```
SecRule REQUEST_URI "@contains /xmlrpc.php" "id:9301,phase:1,deny,log,msg:'CatAI: block URL path containing /xmlrpc.php'"
```

Rules can match on the URL path, query string, request body, headers, or user agent. See [catai.md](catai.md) for why this is a constrained builder rather than a free-text SecLang field.

## Sensitive file protection

Separate from the CRS, and one of the highest-value settings here. Five graduated levels (SFL 0–4) block access to files that should never be public — `.env`, `.git`, backups, config files, editor swap files:

```
GET/POST  /api/sensitive/level      # 0–4
GET/POST  /api/sensitive/block      # add a specific path
GET       /api/sensitive/blocked    # what's currently blocked
POST      /api/sensitive/scan       # walk the real webroot
```

The scanner reports what it actually found in `WEBROOT_PATH`. With that unset it says so plainly rather than inventing findings.

## Access control

```
POST      /api/ip/add               # add to allowlist or blocklist
GET       /api/ip/blacklist
GET       /api/ip/whitelist
DELETE    /api/ip/:list/:ip
GET/POST  /api/geo                  # country blocking
DELETE    /api/geo/:cc
```

Blocking an address or range that contains your own is refused — you can't lock yourself out of the dashboard this way.

## Checking your work

- **Setup Diagnostics** (`/diagnostics`) — is Caddy running, is the WAF actually in the request path, is the database writable. Start here when something seems wrong.
- **Security Score** (`/security-score`) — a graded checklist of your real configuration with specific fixes.
- **Origin Exposure Scanner** (`/origin-scanner`) — confirms your real server isn't reachable around the WAF. A protected site with an exposed origin is not protected.

And the direct test — these should all come back blocked:

```bash
curl "https://yoursite.com/?id=1+UNION+SELECT+1,2,3--"
curl "https://yoursite.com/?q=<script>alert(1)</script>"
curl -A "sqlmap/1.0" https://yoursite.com/
```

If they don't, the usual cause is the Caddyfile missing `order coraza_waf first`, which silently lets traffic skip inspection entirely. Setup Diagnostics checks for exactly that.
