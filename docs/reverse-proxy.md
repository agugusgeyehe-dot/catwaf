# Reverse Proxy Setup

CatWAF's dashboard doesn't proxy traffic itself — Caddy does, with the Coraza module inspecting every request. The dashboard's job is to keep your Caddyfile's WAF block in sync with whatever you configure in the UI.

## How the sync actually works

When you change WAF settings and apply them, `services/caddy.js` looks for a block in your Caddyfile marked with:

```
# @@CATWAF_WAF_START@@
...
# @@CATWAF_WAF_END@@
```

- **If that block already exists**, everything between the markers gets replaced with freshly generated directives.
- **If it doesn't exist yet**, CatWAF inserts a new block just before the *last* closing `}` in the file.

That second case means your Caddyfile needs at least one site block already defined — pointing at your actual application — before the first time you apply a WAF change.

## Minimal starting Caddyfile

```caddyfile
:8081 {
    reverse_proxy localhost:3001
}
```

Replace `localhost:3001` with wherever your real application actually runs, and `:8081` with whatever port you want the *protected* version of your app reachable on. Save this as `/etc/caddy/Caddyfile` (or wherever `CADDYFILE_PATH` points — see `.env.example`), then hit any "Apply" action in the dashboard once. CatWAF will insert its block automatically, right before the closing brace, so you end up with something like:

```caddyfile
:8081 {
    reverse_proxy localhost:3001

    # @@CATWAF_WAF_START@@
    coraza_waf {
        directives `
            ...generated from your WAF settings...
        `
    }
    order coraza_waf first
    # @@CATWAF_WAF_END@@
}
```

You shouldn't need to hand-edit anything between those markers — that's exactly what the dashboard's "Apply" actions, Panic Mode, and Configuration Linter operate on.

## Multiple sites

If you're protecting more than one app, give each its own site block in the same Caddyfile (or split into separate files with `import`, which Caddy supports natively). CatWAF's current WAF state is applied to whichever block contains the marker — running multiple independently-configured WAF instances from one CatWAF install isn't supported yet (see the multi-node section of `ROADMAP.md`).

## Checking it actually took effect

- `GET /api/diagnostics` (or **Setup Diagnostics** in the sidebar) checks that the Caddyfile actually contains a `coraza_waf` block and that `order coraza_waf first` is present — a request can silently sail through Coraza entirely without that ordering directive.
- `GET /api/caddy/status` reports whether Caddy is running and returns the current Caddyfile content, if you want to eyeball it directly.
- The three `curl` commands in the main README's Quick Start section are the fastest real-world check — if none of them get blocked, start with the linter.


## Where CatWAF writes

CatWAF patches its Coraza directives into a real Caddyfile between `# @@CATWAF_WAF_START@@` / `# @@CATWAF_WAF_END@@` markers — it does not keep a separate WAF config.

Which file it picks is printed at startup:

```
[CatWAF] Caddy  /etc/caddy/Caddyfile (auto-detected)
```

With `CADDYFILE_PATH` unset it works this out itself: the `--config` path from Caddy's systemd unit first, then any Caddyfile that already carries CatWAF's markers, then the conventional locations (`<project>/Caddyfile`, `/etc/caddy/Caddyfile`, `/usr/local/etc/caddy/Caddyfile`, and the Homebrew paths on macOS). If none exist yet, it uses `<project>/Caddyfile` and creates it on first write.

Setting `CADDYFILE_PATH` overrides all of it — detection never overrules an explicit setting.

**If the detected file isn't writable by the user CatWAF runs as**, it says so at startup and every WAF change fails with an explanation rather than silently doing nothing. That usually means CatWAF is running unprivileged against a root-owned `/etc/caddy/Caddyfile`: either run it as a user that can write that file, or point `CADDYFILE_PATH` at one you can write and have Caddy load that instead.
