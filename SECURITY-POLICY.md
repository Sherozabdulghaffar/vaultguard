# Security Policy

## Supported Versions

| Version | Supported          |
| ------- | ------------------ |
| 1.0.x   | :white_check_mark: |

Only the latest stable release receives security updates. Please upgrade to the latest version.

## Reporting a Vulnerability

**Please do NOT report security vulnerabilities via public GitHub issues.**

Instead, report them privately via one of these channels:

- **Email:** shahrozgaffar50@gmail.com (replace with your actual security email)
- **GitHub Security Advisories:** Use the "Report a vulnerability" tab in this repository's Security section

### What to Include

Please provide as much detail as possible:

1. **Description** — What is the vulnerability? How does it work?
2. **Impact** — What can an attacker achieve? (data exposure, code execution, privilege escalation, etc.)
3. **Reproduction steps** — Minimal steps to reproduce
4. **Environment** — OS, VaultGuard version, browser/extension version
5. **Proof of concept** — Code, screenshots, or exploit script (if safe to share)
6. **Suggested fix** — If you have ideas for remediation

## Response Timeline

| Phase | Timeline |
|-------|----------|
| **Acknowledgment** | Within 48 hours |
| **Initial assessment** | Within 7 days |
| **Fix development** | Within 30 days (critical: 7 days) |
| **Release & disclosure** | Coordinated with reporter |

We will keep you informed of progress throughout the process.

## Disclosure Policy

- **Coordinated disclosure** — We ask that you give us reasonable time to fix the issue before public disclosure
- **Credit** — We will publicly acknowledge your contribution (unless you prefer anonymity)
- **CVE** — We will request a CVE identifier for confirmed vulnerabilities

## Security Model Summary

VaultGuard is designed with these security principles:

| Area | Implementation |
|------|----------------|
| **Encryption** | AES-256-GCM (PBKDF2, 600k iterations, SHA-256) |
| **Key derivation** | Per-vault random salt, per-write random IV + tag |
| **Biometric keys** | Encrypted via Windows DPAPI (`Electron safeStorage`) |
| **Transport** | Native Messaging (stdio) + loopback HTTP with per-pair tokens |
| **Storage** | Local SQLite only — zero network calls |
| **Dependencies** | Pinned, minimal, audited (no `node_modules` in extension) |

## Out of Scope

The following are **not** considered vulnerabilities:

- Issues requiring physical access to an unlocked device
- Attacks on the underlying OS/browser/Electron (report to those vendors)
- Social engineering / phishing / user error
- Lack of features (e.g., no cloud sync is by design)
- Theoretical attacks without practical exploit on supported versions

## Contact

For any security concerns, contact us at **shahrozgaffar50@gmail.com** (replace with your actual email).

---

*This policy is adapted from industry best practices. Last updated: 2026*
