# Cloudflare Integration

If your app sits behind Cloudflare, the biggest risk to a WAF setup isn't Coraza missing an attack — it's an attacker finding your *real* origin IP and hitting it directly, skipping Cloudflare (and CatWAF) entirely. The Cloudflare Wizard walks through closing that gap end to end.

You'll need a Cloudflare API token with DNS-edit and zone-settings-edit permissions for the zone you're protecting.

## The 7 steps

1. **Verify token & list zones** — `POST /api/cloudflare/zones` confirms your token works and shows every zone it can see.
2. **Verify DNS** — `POST /api/cloudflare/verify-dns` fetches the A records for your chosen zone.
3. **Enable proxy (orange cloud)** — `POST /api/cloudflare/enable-proxy` turns on Cloudflare's proxying for your A record, which is what actually hides your origin IP from public DNS lookups.
4. **Set SSL to Full (Strict)** — `POST /api/cloudflare/ssl-strict` requires your origin to present a valid certificate, closing the gap where traffic between Cloudflare and your origin is unencrypted or unverified.
5. **Generate an origin certificate** — `POST /api/cloudflare/gen-cert` generates a keypair locally (the private key never leaves your server), requests a Cloudflare Origin CA certificate for it, and saves both under `data/certs/`.
6. **Lock the origin firewall** — `POST /api/cloudflare/lock-origin` pulls Cloudflare's current published IP ranges and writes a Caddy rule that rejects any request *not* coming from one of those ranges. This is the step that actually closes the bypass — even if someone finds your real IP, direct requests get a 403.
7. **Run the connectivity test** — `POST /api/cloudflare/test` checks all of the above end to end: domain reachable over HTTPS, served by Cloudflare, proxy actually on, SSL mode actually strict, and the origin firewall rule actually present in your Caddyfile.

Run step 7 again any time you're not sure the setup is still intact — it's a real check against the live domain and current Caddyfile, not a cached status.

## Origin Exposure Scanner

Separately from the wizard, `POST /api/scanner/origin-exposure` checks whether your backend is reachable directly on a given IP/port — the exact failure mode step 6 exists to prevent. Worth running periodically even after the wizard is complete, since infrastructure changes (a new load balancer, a misconfigured security group) can reopen this without touching Cloudflare or Caddy at all.

Scanning an IP requires confirming you own or are authorized to test it (`authorized: true` in the request, or the checkbox on the Origin Exposure Scanner page) — the scanner makes a real outbound connection to whatever host you give it.

## A note on scope

The wizard operates on one zone/domain per run. If you're protecting multiple domains behind Cloudflare, you'll go through the relevant steps once per domain — this isn't wired up as a bulk operation yet (see `ROADMAP.md`).

---

CatWAF is not affiliated with or endorsed by Cloudflare, Inc. It uses Cloudflare's public API with credentials you supply.
