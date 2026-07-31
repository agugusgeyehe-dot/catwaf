---
id: paranoia-levels
title: Paranoia levels 1 to 4
keywords: [paranoia, level, strict, sensitivity, aggressive, tuning, pl1, pl2, pl3, pl4, raise, lower]
questions:
  - What is paranoia level?
  - Which paranoia level should I use?
  - How do I make the firewall stricter?
  - Set paranoia to 4
related: [false-positives, engine-modes, security-score]
actions: [paranoia.set]
---

Paranoia level controls how suspicious the OWASP rules are. Higher levels catch more
attacks and also flag more normal traffic.

| Level | Catches | False positives |
|---|---|---|
| **1** | Clear, unambiguous attacks | Very rare — safe default |
| **2** | Adds pattern-based detection | Occasional |
| **3** | Aggressive heuristics | Common without tuning |
| **4** | Maximum, very strict | Frequent — needs real tuning |

## Which one?

**Level 1** is the right starting point for almost every site, and a perfectly
reasonable permanent setting. It blocks SQL injection, XSS, command injection and the
rest of the well-understood attack classes with almost no risk to real visitors.

**Level 2** is a sensible step up once you've run at level 1 for a while and seen no
false positives.

**Levels 3 and 4** assume you're willing to investigate blocked requests and add
exclusions for your own app's quirks. Don't jump straight to 4 on a live store — you
will block customers.

Raising the level takes effect immediately. If legitimate traffic starts getting blocked
afterward, lower it again and see *When legitimate visitors get blocked*.
