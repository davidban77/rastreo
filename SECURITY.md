# Security Policy

Thanks for helping keep rastreo and its users safe. This document explains which versions receive security fixes, how to report a vulnerability, and what to expect after you do.

## Supported versions

rastreo is pre-1.0 software under active development. Only the latest minor release receives security fixes. Earlier minor releases are end-of-support the moment a new minor ships.

| Version  | Supported          |
| -------- | ------------------ |
| v0.2.x   | Yes                |
| < v0.2.0 | No                 |

Once v1.0 ships, this policy will widen to cover the previous minor release as well.

## Reporting a vulnerability

Please report vulnerabilities privately. Do not open a public GitHub issue.

The preferred channel is GitHub's private security advisory feature:

https://github.com/davidban77/rastreo/security/advisories/new

If GitHub advisories are not usable for you (account issues, embargoed disclosure with a coordinating party, etc.), email davidflores77@gmail.com instead.

When you report, please include:

- A description of the vulnerability and its impact.
- Steps to reproduce, or a proof-of-concept.
- The affected version (`rastreo --version`) and platform.
- Any suggested mitigation, if you have one.

## Response timeline

rastreo is maintained by a single maintainer. Realistic expectations:

- **Acknowledgement**: within 7 days of your report.
- **Initial assessment**: within 14 days, including severity rating and reproduction status.
- **Fix or disclosure plan**: within 30 days, including a target release version and proposed public disclosure date.

If a report turns out to be a non-issue or out of scope, you will receive that decision and the reasoning within the same windows.

## Scope

In scope:

- The `rastreo-core`, `rastreo`, and `rastreo-server` Rust crates published from this repository.
- The official Docker image published from this repository.
- The official Helm chart published from this repository.

Out of scope:

- Vulnerabilities in upstream dependencies. Please report those to the upstream project first. If the upstream fix requires changes here (version bump, code adjustment), open a follow-up report so we can track it.
- Issues in self-built deployments where the source code has been modified.
- Denial-of-service against deliberately exposed surfaces in pre-production scenarios (rastreo is a probing tool — probing yourself harder than the tool defaults is not a vulnerability).
- Issues that require an already-compromised host or already-leaked credentials to exploit.

## Coordinated disclosure

Once a fix is available, we will:

1. Publish a patched release.
2. Publish a GitHub security advisory with the CVE (if assigned), affected versions, and upgrade guidance.
3. Credit the reporter, unless you ask to remain anonymous.

Thanks again for reporting responsibly.
