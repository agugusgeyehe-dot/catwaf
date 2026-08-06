# Plugins

A CatWAF plugin is **data**. It cannot ship code, cannot reference code, and
there is no code path in CatWAF that would run it if it tried.

That is the whole design, and it is a deliberate limitation rather than a stage
on the way to something richer. Loading third-party code into the backend of a
firewall is a direct path to full compromise the moment a plugin — or the URL
it came from, or the account that publishes it — turns out to be malicious.
CatWAF sits in front of your application holding your certificates and your
admin credentials. It is the wrong process to run other people's code in.

- [What a plugin may declare](#what-a-plugin-may-declare)
- [Manifest format](#manifest-format)
- [Directive templates](#directive-templates)
- [What is refused](#what-is-refused)
- [Signing and trust](#signing-and-trust)
- [Installing and removing](#installing-and-removing)

---

## What a plugin may declare

| Field | What it does |
|---|---|
| `settings_defaults` | Default values for existing settings groups, validated against the same schema the API enforces |
| `knowledge` | Text entries the docs panel and CatAI can surface |
| `caddy_templates` | Caddy directives in a constrained placeholder syntax |

That is all. A plugin cannot add a settings group, an API endpoint, a page, a
background job or a request handler — those are all code.

---

## Manifest format

```json
{
  "catwaf_plugin": 1,
  "id": "acme-corp-baseline",
  "name": "Acme Corp baseline",
  "version": "1.2.0",
  "description": "Our standard hardening for public sites.",

  "settings_defaults": {
    "headers": { "preset": "strict", "hsts_max_age": 31536000 },
    "compression": { "enabled": true },
    "access": { "enforce_method_allowlist": true }
  },

  "knowledge": [
    {
      "title": "Why we require the method allowlist",
      "body": "Every service we run speaks GET, POST and HEAD..."
    }
  ],

  "caddy_templates": [
    {
      "context": "per-site",
      "template": "header X-Acme-Policy {{settings.headers.preset}}"
    }
  ]
}
```

`id` must match `^[a-z][a-z0-9-]{1,63}$`. A manifest is capped at 256 KB.

`settings_defaults` is validated **at install time** against the live schema,
not when it is later applied. A plugin referencing a group or field that does
not exist, or a value that would not validate, is refused on installation
rather than producing a broken configuration later.

Applying the defaults is a separate, explicit step — installing a plugin never
silently changes your configuration:

```
POST /api/plugins/<id>/apply-defaults
```

---

## Directive templates

Templates are inserted into one of five named contexts:

| `context` | Where the directive lands |
|---|---|
| `global-http` | Caddy's global options block |
| `per-site` | Inside the protected site's block |
| `catch-all` | The unknown-Host catch-all block |
| `waf-global` | The global Coraza directives |
| `waf-per-site` | The per-site Coraza directives |

The only placeholder permitted is `{{settings.<group>.<field>}}`, and it is
checked at install time against the real schema:

- an unknown group or field is refused;
- a **write-only (secret) field is refused**, so a template cannot exfiltrate a
  key by interpolating it into a header;
- any other brace pair — including ordinary Caddy placeholders like
  `{{http.request.header.Cookie}}` — is refused, so a template cannot reach
  request data it has no business seeing;
- backticks are refused, because a backtick opens a Caddy heredoc and would let
  a template escape its own directive.

Interpolated values are themselves sanitised on the way out: quotes, braces,
backslashes and newlines are stripped, and lists are emitted as separate quoted
tokens.

A template that passes all of this still goes through the ordinary apply
pipeline — rendered, validated by Caddy, and rolled back if the result would
not load.

---

## What is refused

Any manifest containing one of these fields is rejected outright:

```
code   script   main    require   exec
hooks  command  entry   eval      middleware
```

It is rejected rather than ignored, and this is the important part. A plugin
written against some imagined future "real plugins" API fails loudly at install
time with an explanation, instead of installing cleanly and appearing to work
while its most important half does nothing.

```
$ curl -X POST .../api/plugins -d '{"catwaf_plugin":1,"id":"x","hooks":{...}}'
{
  "detail": "This manifest declares \"hooks\". CatWAF plugins are data only —
             they cannot ship or reference executable code, and CatWAF has no
             mechanism that would run it. Rewrite the plugin using
             settings_defaults, knowledge or caddy_templates."
}
```

A plugin also may not ship credentials: a `settings_defaults` entry naming a
secret field is refused.

---

## Signing and trust

Signatures are Ed25519 over the manifest with the `signature` field removed.
Trusted public keys are configured in the environment, base64-encoded and
comma-separated:

```
CATWAF_PLUGIN_KEYS=MCowBQYDK2VwAyEA...,MCowBQYDK2VwAyEA...
```

| | Unsigned | Signed, untrusted key | Signed, trusted key |
|---|---|---|---|
| Install by hand | yes, labelled `unsigned` | yes, labelled `unsigned` | yes |
| Install from a URL | **no** | **no** | yes |

Installing from a URL means fetching a manifest over the network and applying
it, so it requires a signature from a key you have listed. Pasting a manifest
you have read is a different act, and is allowed either way — but the plugin is
labelled `unsigned` everywhere it appears, including in the dashboard list.

URL fetches go through the same SSRF guard as every other outbound request in
CatWAF, so a plugin URL cannot be used to probe your internal network.

---

## Installing and removing

In the dashboard: **Configuration → Advanced**, which also shows the policy
statement above the plugin list.

Via the API:

```
GET    /api/plugins                      # installed plugins and the policy
POST   /api/plugins                      # install from a pasted manifest
POST   /api/plugins/from-url             # { "url": "https://..." } — signature required
POST   /api/plugins/<id>/enabled         # { "enabled": true|false }
POST   /api/plugins/<id>/apply-defaults  # apply settings_defaults now
DELETE /api/plugins/<id>
```

Disabling a plugin stops its templates being rendered and its knowledge entries
being surfaced. It does **not** revert settings its defaults have already been
applied to — those are your settings now, and silently reverting them would be
a surprise. Change them back with `catwaf settings` or a template.

---

## See also

- [Settings reference](settings.md) — the groups and fields a plugin may target
- [Protection layer](protection.md)
- `raw_config` in the [settings reference](settings.md#raw_config) — the
  unmanaged escape hatch for directives CatWAF does not model, if a plugin is
  more structure than you need
