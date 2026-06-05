# Security Policy

## Supported Versions

| Version | Supported          |
| ------- | ------------------ |
| 0.1.x   | Yes — active development |
| < 0.1   | No                 |

## Reporting a Vulnerability

**Please do NOT report security vulnerabilities via GitHub Issues.**

Security vulnerabilities in AgentAuth can expose agent credentials, allow privilege escalation, or compromise the integrity of audit logs. We take every report seriously and aim to respond within 48 hours.

### How to Report

1. **Email:** security@agentauth.io
2. **GitHub Private Vulnerability Reporting:** Use the "Security" tab on GitHub to submit a private advisory.

### What to Include

Please include as much of the following as possible:

- A description of the vulnerability and its potential impact
- Steps to reproduce the vulnerability
- Affected versions
- Any suggested mitigations or patches

### PGP Key

For sensitive reports, encrypt your message using our PGP key:

```
-----BEGIN PGP PUBLIC KEY BLOCK-----
[PGP key will be published at https://agentauth.io/.well-known/security.txt]
-----END PGP PUBLIC KEY BLOCK-----
```

## Response Process

1. **Acknowledgement:** Within 48 hours of receipt
2. **Initial assessment:** Within 5 business days
3. **Fix timeline:** Depending on severity:
   - Critical (CVSS 9.0+): Fix within 7 days
   - High (CVSS 7.0–8.9): Fix within 14 days
   - Medium/Low: Fix within 30 days
4. **CVE assignment:** We will request a CVE for confirmed vulnerabilities
5. **Public disclosure:** Coordinated with the reporter; typically 90 days after fix

## Security Design Principles

AgentAuth is designed with the following security principles:

### Defense in Depth
- Every credential is short-lived and resource-scoped
- Multiple layers of validation (envelope signature, policy engine, revocation check)
- No long-lived passwords or API keys in the hot path

### Least Privilege by Default
- New tenants start with a restrictive default policy
- Sub-agents can never escalate beyond their parent's scope
- Tool scope must be explicitly declared — no implicit access

### Cryptographic Guarantees
- Agentic envelopes are signed with ES256 (ECDSA P-256)
- DPoP binding prevents token theft even if intercepted
- Audit log hash chain detects tampering

### Zero Trust
- Every request is authenticated, regardless of network location
- Agent identity is re-verified on every token mint
- Revocation takes effect immediately

## Known Limitations

- The current `EnvelopeVerifier._decode_unverified()` fallback in the Python SDK bypasses signature verification. This is explicitly marked for development use only and should never be used with a real signing key.
- The `JoinTokenAttestor` is designed for development/testing only and should not be used in production.
- The development CLI flag `--skip-verify` (if present) must not be used in production deployments.

## Security Hardening Checklist

Before deploying to production:

- [ ] Generate a proper ECDSA P-256 signing key pair (do not use defaults)
- [ ] Set `AGENTAUTH_JWT_SIGNING_KEY` to a cryptographically random 32+ byte value
- [ ] Enable TLS on the server (use a reverse proxy or configure TLS directly)
- [ ] Restrict network access to the AgentAuth API (not public-facing)
- [ ] Set `pod-security.kubernetes.io/enforce: restricted` on the namespace
- [ ] Enable audit log export to immutable storage (S3/GCS)
- [ ] Configure PostgreSQL with SSL and proper credentials
- [ ] Do not use `JoinTokenAttestor` in production
- [ ] Review and tighten the default policy for your use case
