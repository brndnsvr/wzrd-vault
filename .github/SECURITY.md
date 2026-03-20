# Security Policy

## Reporting a Vulnerability

If you discover a security vulnerability in wzrd-vault, please report it
responsibly using [GitHub's private vulnerability reporting](https://github.com/brndnsvr/wzrd-vault/security/advisories/new).

**Do NOT open a public GitHub issue for security vulnerabilities.**

You should receive a response within 72 hours. We will work with you to
understand the issue and coordinate a fix before any public disclosure.

## Scope

The following are in scope:
- Secrets leaking to process arguments, environment, logs, or temp files
- Encryption/decryption flaws
- Passphrase handling weaknesses
- Path traversal or injection in secret paths
- Temp file cleanup failures in `wzrd-vault edit`

## Supported Versions

Only the latest release is supported with security updates.
