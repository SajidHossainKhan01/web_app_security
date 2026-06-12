# Reverse Proxy & WAF — CSE804

## Architecture
```
Internet → [Edge CDN/WAF] → [Nginx+ModSecurity] → [App Servers] → [DB]
```
**Key principle:** Reverse proxy is the sole TLS endpoint. Origin servers never receive raw Internet connections.

## Security Controls
| Control | Description |
|---|---|
| TLS Termination | Offloads decryption; enforces TLS 1.2+/1.3 |
| Security Headers | HSTS, CSP, X-Frame-Options injected centrally |
| WAF | Layer 7 inspection for OWASP Top 10 |
| Rate Limiting | Per-IP; 5/min on login (credential stuffing protection) |
| Header Stripping | Server, X-Powered-By removed (no version disclosure) |
| mTLS to Backend | Proxy authenticates origin servers |
| X-Forwarded-For | Always overwrite with real TCP source (never trust client) |

## WAF: OWASP CRS Anomaly Scoring
Each rule match adds points: CRITICAL=5, ERROR=4, WARNING=3.
Block when total >= threshold (default 5).

**WAF Tuning Workflow:**
1. Deploy `DetectionOnly` — no blocking
2. Collect 72h of logs
3. Identify false positives → create exclusions
4. Switch to `SecRuleEngine On`
5. Monitor daily

## TLS Bypass Categories (do NOT inspect)
- Banking / financial portals (legal/privacy)
- Healthcare systems (HIPAA)
- Certificate-pinned apps
- Personal email (employee privacy policy)
