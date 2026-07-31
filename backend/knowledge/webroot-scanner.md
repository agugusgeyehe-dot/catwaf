---
id: webroot-scanner
title: Scanning your webroot for exposed files
keywords: [scan, scanner, webroot, exposed, public, discover, find files, audit, directory, listing, WEBROOT_PATH]
questions:
  - How do I find exposed files on my site?
  - What does the webroot scanner do?
  - Why is my scan empty?
  - How do I set the webroot path?
related: [sensitive-files]
actions: []
---

The webroot scanner walks your site's public directory and lists what's actually there,
flagging anything risky — config files, backups, scripts with dangerous names.

## Setting it up

The scanner needs to know where your public files live. Set `WEBROOT_PATH` in your `.env`
file and restart CatWAF:

```
WEBROOT_PATH=/var/www/html
```

Until that's set, the scanner reports that it isn't configured. It does **not** show
example results — a security tool inventing findings for a directory it never read would
be worse than useless.

## Reading the results

Files are categorised and risk-rated:

- **Critical** — config files, backups, credentials, version control, anything matching a
  known webshell name.
- **High** — PHP scripts that commonly get abused: uploaders, installers, admin entry
  points.
- **Low** — ordinary static content.

Click any file to block access to it immediately.

## An empty result is a real result

If the scan completes and finds nothing, that's genuinely what's in the directory — not a
failure. If you expected files, check that `WEBROOT_PATH` points where you think it does.
