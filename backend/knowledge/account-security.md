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

This edition supports one admin account, for one site owner. It doesn't include team management or additional logins — that's intentionally out of scope for the free, single-owner edition.

## What's actually protecting your login

- Passwords are hashed, never stored in plain text.
- Login attempts are rate-limited per IP and per username, so brute-forcing your password isn't practical.
- Sessions use a signed token that expires — there's no permanent "remember me" credential sitting in a cookie somewhere.
- The API itself doesn't sit at a fixed, guessable address — see the README's Security section if you're curious how that works.

If you ever suspect your password has leaked, the safest move is rotating it on the server as above and checking the audit log for anything unfamiliar.
