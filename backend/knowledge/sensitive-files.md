---
id: sensitive-files
title: Sensitive file protection (SFL levels)
keywords: [sensitive, files, sfl, config, backup, env, git, hidden, expose, secret, dotfile, wp-config, leak]
questions:
  - What is SFL?
  - How do I stop people reading my .env file?
  - What are the sensitive file levels?
  - How do I block access to config files?
related: [webroot-scanner, paranoia-levels]
actions: []
---

Sensitive File Levels (SFL) block requests for files that should never be reachable from
the internet — even if they're sitting in your webroot by mistake.

This matters because the most damaging leaks are rarely clever attacks. They're a `.env`
file with database credentials, a `.git` directory exposing your whole source history, or
`backup.sql` left in the web directory after a migration.

| Level | Blocks |
|---|---|
| **0** | Nothing (off) |
| **1** | Obvious secrets — `.env`, `.git`, config files |
| **2** | Adds upload endpoints and common shell filenames |
| **3** | Adds admin panels and database managers |
| **4** | Matches those paths at *any* depth, e.g. `/en/v2/.env` |

## Which level?

**Level 1 is safe for essentially every site** and blocks the highest-value targets. It's
hard to imagine a legitimate reason for a visitor to fetch your `.git/config`.

**Level 4** is the strictest and catches paths nested anywhere in your URL structure.
It's worth testing before you leave it on, since a legitimately-named path in your app
could collide.

## This is a safety net, not a fix

SFL stops the file being *served*. It doesn't remove it. If a `.env` was ever publicly
reachable, treat those credentials as compromised and rotate them — then delete the file
from the webroot.
