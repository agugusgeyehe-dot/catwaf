# TLS and certificates

Caddy obtains and renews certificates automatically, and for most installs
nothing on this page needs changing. It exists for the cases where the default
does not fit: an origin that cannot be reached on port 80, a wildcard, a
certificate your organisation issues, or a compliance requirement about
protocol versions.

```
catwaf settings tls
```

Or **Configuration → TLS & Certificates** in the dashboard, which also shows
the certificates Caddy currently holds and how many days each has left.

- [Certificate sources](#certificate-sources)
- [Getting to HTTPS on the first request](#getting-to-https-on-the-first-request)
- [ACME challenges and wildcards](#acme-challenges-and-wildcards)
- [When issuance fails](#when-issuance-fails)
- [Protocol strictness](#protocol-strictness)
- [Client certificates](#client-certificates)
- [Admin sessions](#admin-sessions)

---

## Certificate sources

| `cert_source` | Where the certificate comes from |
|---|---|
| `acme` | Let's Encrypt or ZeroSSL, obtained and renewed by Caddy (default) |
| `self-signed` | Issued locally by Caddy's internal CA |
| `custom` | A certificate and key you supply |

### Custom certificates

Paste both the certificate and its key. **Check them before applying:** a
certificate that does not match its key does not fail at apply time — it fails
when a visitor tries to connect, which is a much worse moment to find out.

The dashboard has a checker that reports the subject, the hostnames the
certificate actually covers, its expiry, and whether the key matches. Via the
API:

```
POST /api/tls/validate   { "certificate": "-----BEGIN CERTIFICATE-----...", "key": "..." }
```

The key is write-only. It is stored and never sent back to the browser or
printed by the CLI.

### Self-signed

`self-signed` uses Caddy's internal CA. Browsers will warn, so this is for
development, for an origin behind another terminating proxy, or as a temporary
state — not for a public site.

---

## Getting to HTTPS on the first request

`self_signed_fallback` is **on by default** and solves a specific problem: DNS
has not propagated yet, so ACME cannot validate, so there is no certificate,
so the site serves plaintext or nothing at all during exactly the window when
someone is most likely to be testing it.

With the fallback on, CatWAF serves a locally-issued certificate until the real
one arrives, then switches. The site is on HTTPS from the first request. A
browser warning during setup is a better failure than an unencrypted login
form.

---

## ACME challenges and wildcards

| `acme_challenge` | Needs | Use when |
|---|---|---|
| `http-01` | port 80 reachable from the internet | the normal case (default) |
| `tls-alpn-01` | port 443 reachable | port 80 is blocked |
| `dns-01` | a DNS provider API token | wildcards, or an origin the internet cannot reach |

`dns-01` is the only option that can issue a **wildcard** certificate, and the
only one that works for a host with no public inbound path at all.

```
catwaf settings tls acme_challenge=dns-01 dns_provider=cloudflare wildcard=true
catwaf settings tls dns_api_token=<token>
```

The token is write-only.

**`dns-01` needs a Caddy build that includes your provider's module.** Caddy
does not ship them all. CatWAF checks before rendering, and if the module is
missing it says so rather than writing a configuration that would fail to
load:

```
$ catwaf doctor
...
! Enabled but not in effect: ACME DNS-01 (cloudflare)
  Needs a Caddy build including the cloudflare DNS provider module
  (xcaddy build --with github.com/caddy-dns/cloudflare).
```

---

## When issuance fails

Two settings exist because ACME failures are usually transient and usually
happen at the worst time.

**`acme_fallback`** tries the other provider when the primary fails or is
rate-limited. Let's Encrypt's rate limits are per-domain and per-week; hitting
one during a botched deploy otherwise means waiting days.

**`acme_retries` / `acme_retry_delay_sec`** control how hard Caddy tries before
giving up. The defaults (3 attempts, 30 seconds apart) cover ordinary DNS
propagation lag.

The dashboard's TLS page shows advice before you apply — for example, that
`dns-01` is selected but no provider token is set, or that a wildcard has been
requested with a challenge type that cannot issue one. Read it; these are the
mistakes that produce a site with no certificate at all.

---

## Protocol strictness

| `profile` | Minimum | Suitable for |
|---|---|---|
| `modern` | TLS 1.3 only | you control the clients, or you have a compliance requirement |
| `intermediate` | TLS 1.2 with a strong cipher list | the default; the right answer for a public site |
| `compatible` | TLS 1.2 with a wider cipher list | a legacy client you cannot upgrade |

`modern` will lock out older clients. That is the point, but check your traffic
before choosing it — the security score page and the request log will tell you
what is actually connecting.

`ocsp_stapling` is on by default. It removes a round trip to the CA from the
client's handshake and stops the CA learning who visits your site.

---

## Client certificates

mTLS requires a client certificate signed by your CA before CatWAF will serve
anything at all. It is the strongest access control here — stronger than basic
auth, an IP allowlist or the challenge gate — because an attacker without a
certificate cannot complete the handshake, let alone reach the application.

```
catwaf settings mtls
```

Suitable for an admin panel, an internal service, or a machine-to-machine API.
Not suitable for anything the public needs to reach.

Two caveats CatWAF states rather than hides:

- **Lock yourself out and the fix is on the server, not in the browser.** Have
  a working client certificate installed before you apply this.
- **`verify_depth` is recorded but not enforced.** Caddy exposes no equivalent
  setting. CatWAF reports it as skipped rather than pretending it is doing
  something, which is why it appears in `catwaf doctor` output.

---

## Admin sessions

Session lifetime is a setting rather than a hardcoded 12 hours, with the
previous value as the default so no existing install's behaviour changed:

```
catwaf settings session absolute_max_age_min=720 idle_timeout_min=60
```

| Field | Meaning |
|---|---|
| `absolute_max_age_min` | Hard lifetime; the session ends regardless of activity |
| `idle_timeout_min` | Ends after this long with no requests (`0` = off) |
| `rolling` | Extend on each request, up to the absolute maximum |
| `bind_ip` | A stolen token stops working from another address |
| `bind_user_agent` | A stolen token stops working in another browser |
| `max_concurrent` | Cap simultaneous sessions per account (`0` = unlimited) |

`bind_ip` has a real cost: it logs users out whenever their address changes,
which on a mobile network or a VPN is often. It is off by default for that
reason, not because it is ineffective.

For a second factor on top of the password, see
[`catwaf 2fa`](cli.md#catwaf-2fa).

---

## See also

- [Settings reference](settings.md#tls) — every field
- [Reverse proxy guide](reverse-proxy.md)
- [Protection layer](protection.md) — what happens after the handshake
