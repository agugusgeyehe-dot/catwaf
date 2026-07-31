---
id: alerts
title: Getting notified about attacks
keywords: [alert, notification, notify, discord, slack, telegram, webhook, email, spike, warn, message]
questions:
  - How do I get notified about attacks?
  - Can CatWAF send me a Discord message?
  - How do I set up alerts?
  - What triggers an alert?
related: [blocked-requests, dashboard]
actions: []
---

CatWAF can push notifications to Discord, Slack, Telegram, or any custom webhook, so you
find out about a problem without having a dashboard open.

## Setting up

Paste the webhook URL for your service on the Alerts page and send a test message to
confirm it arrives. Each service gives you a webhook URL from its own settings — Discord
under *Channel Settings → Integrations*, Slack via an incoming-webhook app.

## Choosing a spike threshold

Alerts fire when blocked requests exceed your threshold within a window. Set it above your
normal background noise.

Every public site gets a constant trickle of automated scanning. If you alert on that,
you'll mute the channel within a day and miss the real incident later. Watch the dashboard
for a few days first, see what "quiet" actually looks like for your site, then set the
threshold comfortably above it.

## What's worth waking up for

A sustained spike from a single source, or a sudden jump in blocked requests after you
changed something, are the two signals worth acting on. Steady low-level scanning is
weather, not news — the firewall is already handling it.
