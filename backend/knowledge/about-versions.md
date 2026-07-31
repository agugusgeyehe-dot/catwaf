---
id: about-versions
title: About CatWAF and version info
keywords: [version, about page, edition, runtime, node version, what version, update, upgrade]
questions:
  - What version of CatWAF am I running?
  - What does the About page show?
  - How do I know if I'm up to date?
related: [settings-appearance, troubleshooting, editions]
actions: []
---

The About page (and the About panel on Settings) reports real information read from the running server at the moment you load the page — not a hardcoded string in the frontend. If you restart or update the backend, this updates automatically the next time you load it.

It shows:

- **Version** — the exact CatWAF release you're running. The current release is 1.0.1.
- **Edition** — Lite or Full. See the editions topic for what each one installs. (This is separate from CatWAF Free, which is the product line this build belongs to.)
- **Engine / Ruleset** — Coraza and OWASP CRS, the actual inspection stack.
- **Runtime** — the Node.js version the backend is running under.

From a terminal, `catwaf version` prints the version and `catwaf edition` prints `lite` or `full`. `catwaf status` shows both together with component health.

If you're reading this in the dashboard, you're on Full — Lite has no web interface.

If you're checking whether you're up to date, compare this version against the project's releases. There's no in-dashboard auto-update — updating means pulling the latest code and restarting, same as any self-hosted install. Re-running the installer, or `git pull && npm install && catwaf setup --<edition>`, both preserve your configuration, database, rules and accounts.
