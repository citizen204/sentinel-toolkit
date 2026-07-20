# Security Policy

## Authorized use

Sentinel is a **defensive, read-only** security toolkit. Only run it against accounts,
systems, and applications you own or are explicitly authorized to audit. The maintainers are
not responsible for misuse.

## Supported versions

Fixes land on the latest minor only. There is no long-term support branch, and this is a
single-maintainer project — plan upgrades accordingly.

| Version | Supported | Notes |
|---------|:---------:|-------|
| 0.2.x   | ✅        | Current. |
| 0.1.x   | ❌        | Report schema 1.x. Its coverage model treats an unrecorded scope as unlimited, which can present an unscanned resource as remediated. Upgrade and re-scan to get a trustworthy baseline. |

## Reporting a vulnerability

Please **do not** open a public issue for security problems.

Instead, report privately via GitHub:
**Security → Advisories → Report a vulnerability**
(<https://github.com/citizen204/sentinel-toolkit/security/advisories/new>).

Include a description, affected version/commit, and reproduction steps. We aim to acknowledge
reports within 7 days and to coordinate a fix and disclosure timeline with you.
