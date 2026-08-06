---
id: account-security
title: Your admin account and login security
keywords: [password, account, login, username, change password, credentials, admin account, forgot password, another user, second account]
questions:
  - How do I change my password?
  - Can I add a second account?
  - I forgot my password
  - Is my login secure?
related: [getting-started]
actions: []
---

CatWAF Free ships with no default accounts at all — `catwaf --setup` is the only way to get one, and it requires you to choose a real password on the spot. There's no admin/admin or viewer/viewer sitting around waiting to be exploited.

## Changing your password

There's currently no in-dashboard way to change your password once it's set. If you need to change it, that has to be done on the server directly (ask whoever manages the server, or see the project's docs for the backend's account functions).

## Multiple accounts

`catwaf --setup` creates one admin account to get you started, but you're not limited to it. From the server, `catwaf user add <username> --role admin|viewer` creates another login — `admin` can change protection settings, `viewer` can only look. Manage them with `catwaf user list`, `catwaf user role`, `catwaf user passwd` and `catwaf user remove`. There's no in-dashboard way to do this yet (see above) — it's a server-side, CLI/API-only capability for now.

## What's actually protecting your login

- Passwords are hashed, never stored in plain text.
- Login attempts are rate-limited per IP and per username, so brute-forcing your password isn't practical.
- Sessions use a signed token that expires — there's no permanent "remember me" credential sitting in a cookie somewhere.
- The API itself doesn't sit at a fixed, guessable address — see the README's Security section if you're curious how that works.

If you ever suspect your password has leaked, the safest move is rotating it on the server as above and checking the audit log for anything unfamiliar.
