# 🛡️ Web & Application Layer Security — Full Implementation

> **Course Project** · CSE804: Network and Internet Security · University of Dhaka
> **Topic:** Web and Application Layer Security — WAF · TLS · OWASP Top 10 · API Security
> **Instructor:** Dr. Tushar, Mosaddek Hossain Kamal · Professor, CSE

[![Python](https://img.shields.io/badge/Python-3.10+-blue)](https://python.org)
[![OWASP](https://img.shields.io/badge/OWASP-Top%2010%202021-red)](https://owasp.org/Top10)
[![License](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

## Overview

Complete implementation of Web and Application Layer Security covering every attack
and defence from the CSE804 lecture with working code, configurations, and tests.

## What Is Implemented

| Category | Contents |
|---|---|
| **Reverse Proxy** | Hardened Nginx, security headers, mTLS, rate limiting |
| **WAF** | ModSecurity + OWASP CRS, anomaly scoring, tuning workflow |
| **TLS** | TLS 1.3, HSTS, OCSP stapling, cipher hardening |
| **SQLi** | All 4 attack types, parameterised query defence |
| **XSS** | Stored/Reflected/DOM, CSP, HTTPOnly, SameSite, encoding |
| **CSRF** | Token pattern, double-submit cookie, SameSite defence |
| **SSRF** | Cloud metadata attack, allowlist + RFC 1918 blocking |
| **XXE** | External entity injection, defusedxml hardening |
| **IDOR** | Object-level auth bypass, ownership checks |
| **API Security** | OAuth 2.0 + PKCE, JWT validation, rate limiting |
| **Auth** | bcrypt/PBKDF2 hashing, session management, lockout |
| **Tests** | 50+ automated tests covering all vulnerability classes |

## Quick Start

```bash
git clone https://github.com/YOUR_USERNAME/web-app-security.git
cd web-app-security
pip install -r requirements.txt
python3 tests/test_all.py      # run full test suite
python3 src/sqli/sqli_demo.py  # SQLi demo
python3 src/xss/xss_demo.py    # XSS demo
python3 src/api/api_security.py # JWT + OAuth demo
./scripts/tls/03_tls_and_headers_audit.sh --headers https://example.com
```

## Architecture

```
Internet → [Edge WAF/CDN] → [Nginx+ModSecurity] → [App Servers] → [DB]
                              TLS terminate          Input validate   Encrypted
                              Security headers       RBAC + AuthZ     AES-256
                              Rate limiting          CSP/CSRF tokens
                              WAF (OWASP CRS)        Prepared stmts
```

## Repository Structure

```
web-app-security/
├── configs/nginx/          Hardened Nginx reverse proxy config
├── configs/modsecurity/    ModSecurity + OWASP CRS WAF config
├── configs/csp/            Content Security Policy examples
├── scripts/waf/            ModSecurity install + tuning scripts
├── scripts/tls/            TLS audit + security headers scanner
├── src/sqli/               SQL injection attack demos + defences
├── src/xss/                XSS (Stored/Reflected/DOM) demos + defences
├── src/csrf/               CSRF attack + token/SameSite defence
├── src/ssrf/               SSRF attack vectors + allowlist defence
├── src/xxe/                XXE attack + parser hardening + IDOR
├── src/api/                JWT validation + OAuth PKCE + rate limiting
├── src/auth/               Password hashing + session management
├── tests/test_all.py       Self-contained test suite (50+ tests)
├── docs/                   Deep-dive reference docs
├── diagrams/               ASCII architecture diagrams
└── examples/               Security scanner + WAF log analyzer
```

## OWASP Top 10 Coverage

| # | Category | Implementation |
|---|---|---|
| A01 | Broken Access Control | `src/xxe/xxe_idor_demo.py` |
| A02 | Cryptographic Failures | `scripts/tls/`, `src/auth/` |
| A03 | Injection (SQLi + XSS) | `src/sqli/`, `src/xss/` |
| A05 | Security Misconfiguration | `configs/` |
| A07 | Auth Failures | `src/auth/`, `src/api/` |
| A10 | SSRF | `src/ssrf/` |

## References

- [OWASP Top 10 2021](https://owasp.org/Top10)
- [OWASP API Security Top 10](https://owasp.org/API-Security)
- [OWASP ModSecurity CRS](https://coreruleset.org)
- [RFC 7519: JWT](https://tools.ietf.org/html/rfc7519)
- [RFC 7636: PKCE](https://tools.ietf.org/html/rfc7636)
- Lecture 04 — CSE804, University of Dhaka (Dr. M. H. K. Tushar, 2026)
