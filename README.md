# security-headers-scanner

A lightweight CLI tool that audits HTTP security headers on any web target — no dependencies beyond the Python standard library.

Checks for missing or misconfigured headers that are commonly flagged in penetration tests and security audits (OWASP, Mozilla Observatory).

---

## What it checks

| Header | Severity | Attack prevented |
|---|---|---|
| `Strict-Transport-Security` | HIGH | SSL stripping, MITM |
| `Content-Security-Policy` | HIGH | XSS, data injection |
| `X-Frame-Options` | MEDIUM | Clickjacking |
| `X-Content-Type-Options` | MEDIUM | MIME sniffing |
| `Referrer-Policy` | LOW | Referrer leakage |
| `Permissions-Policy` | LOW | Feature abuse (camera, mic) |
| `X-XSS-Protection` | LOW | Legacy XSS (older browsers) |

Also flags **server header information disclosure** (e.g. `Server: Apache/2.4.51` leaks version info).

---

## Usage

```bash
# Basic scan
python scanner.py https://example.com

# JSON output (pipe to jq, save to file, feed into other tools)
python scanner.py https://example.com --json
```

No pip install required — uses Python stdlib only (`urllib`, `json`, `sys`).

---

## Example output

```
================================================================
  Security Headers Scanner
  Target : https://example.com
  Time   : 2026-03-25T10:00:00Z
  Status : HTTP 200
================================================================

  MISSING HEADERS

  [!] Strict-Transport-Security
     Severity : HIGH
     Why      : Enforces HTTPS connections (HSTS)
     Fix      : Add: Strict-Transport-Security: max-age=31536000; includeSubDomains; preload

  [!] Content-Security-Policy
     Severity : HIGH
     Why      : Prevents XSS and data injection attacks
     Fix      : Define a strict CSP policy restricting script/style sources

  PRESENT HEADERS

  [+] X-Content-Type-Options
     Value : nosniff

================================================================
  Score : 42/100  |  Grade : C
================================================================
```

---

## Scoring

| Score | Grade |
|---|---|
| 80–100 | A |
| 60–79 | B |
| 40–59 | C |
| 0–39 | F |

---

## Why this matters

Security headers are a first line of defence — cheap to add, commonly forgotten. They're part of every standard web pentest checklist (OWASP Top 10, NIST, PCI-DSS). Missing them doesn't mean you're breached; it means you're leaving easy wins on the table.

---

## Roadmap

- [ ] Cookie flag analysis (`Secure`, `HttpOnly`, `SameSite`)
- [ ] CORS misconfiguration detection
- [ ] Redirect chain following (HTTP → HTTPS check)
- [ ] Batch scanning from a list of URLs
- [ ] HTML report output
