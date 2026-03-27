# NullGrids Red vs Blue — Enterprise Cyber Range
### Version 1.0 | Competition-Grade Cybersecurity Simulation Platform

---

## QUICK START (3 Commands)

```bash
pip install flask
python app.py
# Open http://localhost:5000
```

---

## WHAT IS THIS?

NullGrids is a self-contained, single-file Flask application that simulates a realistic enterprise breach scenario for cybersecurity competitions. It supports four simultaneous team roles:

| Team | Role | Entry Point |
|------|------|-------------|
| 🔴 Red Team | Attacker — execute a 12-stage attack chain | `/login` |
| 🔵 SOC | Monitor live logs, detect attacks, tag IPs, escalate | `/soc/monitor` |
| 🔬 DFIR | Investigate forensics, contain the breach | `/dfir` |
| 📋 GRC | Evaluate governance gaps, score compliance | `/grc/dashboard` |

---

## LOGIN CREDENTIALS

| Role | Username | Password |
|------|----------|----------|
| Red Team | `jdoe` | `password123` |
| Red Team (admin) | `admin` | `admin123` |
| SOC Analyst | `soc_analyst` | `SOCpass2024!` |
| DFIR Lead | `dfir_lead` | `DFIRpass2024!` |
| GRC Manager | `grc_manager` | `GRCpass2024!` |

> Red Team: Brute force the login first (5+ failed attempts triggers Stage 1)

---

## PLATFORM ROUTES

| Route | Description | Access |
|-------|-------------|--------|
| `/` | MeridianTech company homepage | Public |
| `/login` | Employee login — Red Team entry | Public |
| `/dashboard` | Post-login user panel | Authenticated |
| `/search?q=` | Employee search — **SQLi vector** | Authenticated |
| `/profile` | Profile settings — **SSRF vector** | Authenticated |
| `/upload` | File manager — **Webshell + RCE vector** | Authenticated |
| `/employee?id=` | Employee record — **IDOR vector** | Authenticated |
| `/admin` | Admin console — **Privilege escalation** | Admin (or post-Stage 7) |
| `/financials` | Financial data — **Exfiltration target** | Authenticated |
| `/soc/monitor` | SOC SIEM dashboard | SOC / Admin |
| `/dfir` | DFIR portal (locked until breach ≥60% + escalation) | DFIR / Admin |
| `/grc/dashboard` | GRC gap analysis & risk register | GRC / Admin |
| `/grc/mentor` | GRC control evaluator | GRC / Admin |
| `/api/win_conditions` | Live competition state JSON | Public |
| `/mentor/reset` | Reset all competition data | POST with key |

---

## 12-STAGE ATTACK CHAIN

| Stage | Name | Trigger | Breach Δ | Log Sources |
|-------|------|---------|----------|-------------|
| 1 | Brute Force Login | 5+ failed logins in 30s | +5% | auth, alerts, firewall, IDS |
| 2 | Basic Enumeration | Dashboard/directory browsing | +4% | access, webserver, IDS |
| 3 | SQL Injection | SQLi payload in `/search` | +8% | access, alerts, security, IDS |
| 4 | Credential Discovery | Data extracted via SQLi | +7% | auth, security, endpoint |
| 5 | IDOR Access Expansion | Sequential ID enumeration at `/employee` | +6% | access, alerts, security |
| 6 | SSRF Internal Mapping | Internal IP in `/profile` URL field | +8% | webserver, firewall, IDS |
| 7 | Privilege Escalation | Admin access attempted after Stage 6 | +10% | auth, endpoint, security |
| 8 | Admin Panel Access | `/admin` accessed with escalated token | +9% | access, auth, alerts |
| 9 | File Upload / Webshell | `.php` / `.jsp` file uploaded | +12% | webserver, endpoint, alerts |
| 10 | Remote Command Execution | Command submitted via RCE terminal | +11% | endpoint, syslog, alerts |
| 11 | Financial Data Access | `/financials` accessed | +12% | access, security, alerts |
| 12 | Data Exfiltration | Exfil button triggered | +8% | firewall, IDS, alerts, security |

---

## SOC MONITOR FEATURES

- **Live breach meter** with 12-stage progress bar
- **Attack chain panel** — every detected stage with incident ID, chain ID, attacker IP
- **Real-time log stream** — 9 sources, filterable by source/level/IP/keyword
- **SIGMA rule engine** — 10 rules fire automatically every 10 seconds
- **IP management** — tag IPs as attacker/suspicious/internal, block instantly
- **Escalate to DFIR** — button unlocks DFIR portal when breach ≥60%
- **Win conditions panel** — live Red vs Blue competition state

### SIGMA Rules Active

| ID | Rule | Severity | Stage |
|----|------|----------|-------|
| SIGMA-001 | Brute Force Authentication | HIGH | 1 |
| SIGMA-002 | SQL Injection Attempt | CRITICAL | 3 |
| SIGMA-003 | IDOR Parameter Manipulation | MEDIUM | 5 |
| SIGMA-004 | SSRF Internal Endpoint Probe | HIGH | 6 |
| SIGMA-005 | Privilege Escalation | CRITICAL | 7 |
| SIGMA-006 | Suspicious File Upload | CRITICAL | 9 |
| SIGMA-007 | Remote Command Execution | CRITICAL | 10 |
| SIGMA-008 | Sensitive Data Exfiltration | CRITICAL | 12 |
| SIGMA-009 | Admin Panel Unauthorized Access | HIGH | 8 |
| SIGMA-010 | Lateral Movement / Internal Recon | HIGH | 2 |

---

## DFIR PORTAL

Locked until: **Breach ≥ 60%** AND **SOC has escalated**

### IR Actions & Effects

| Action | Target | Breach Reduction |
|--------|--------|-----------------|
| Block IP | Attacker IP | -5% |
| Disable Account | Username | -8% |
| Revoke Sessions | Username | -5% |
| Remove Malware | (webshell) | -12% |
| Restore Services | (system) | -10% |

### Evidence Collection
- Full attack log bundle with stage correlation
- Timeline reconstruction (chronological attack events)
- Packet capture records mapped to attack stages
- SIGMA trigger records

---

## GRC SYSTEM

### Gap Analysis
Auto-generates from breach state — identifies failing ISO 27001 controls based on which attack stages succeeded.

### Risk Register
Dynamic risk scoring (Likelihood × Impact) — 6 risks tracked, severity updates as breach progresses.

### ISO 27001 Controls (14)
A.5.1 through A.18.1 — submit evidence and implementation status for each. Scored by weight × status multiplier.

### Compliance Score
- Implemented = 100% of control weight
- Partial = 50%
- Planned = 20%
- Not Implemented = 0%

---

## WIN CONDITIONS

| Condition | Winner | Requirement |
|-----------|--------|-------------|
| Red Team Win | 🔴 Red | Stage 12 complete + Breach ≥90% |
| Blue Team Win | 🔵 Blue | DFIR unlocked + ≥3 IR actions + Breach ≤40% |

Check live: `GET /api/win_conditions`

---

## RESET

```bash
curl -X POST http://localhost:5000/mentor/reset \
  -H "Content-Type: application/json" \
  -d '{"key":"NULLGRIDS_MENTOR_RESET"}'
```

Clears: all logs, attack chain, SIGMA triggers, DFIR actions, GRC submissions, packets, IP tags. Resets breach to 0%, re-enables all accounts.

---

## LOG ENGINE

9 simultaneous log streams generated continuously in background:

- `access` — HTTP access logs
- `auth` — Authentication events
- `webserver` — Web server / application logs
- `endpoint` — Host-based security events
- `firewall` — Network firewall rules
- `ids` — Intrusion detection system
- `security` — Security platform events
- `syslog` — System logs
- `alerts` — SIEM alert feed

Includes **false positives** (8% of background traffic) to require analyst reasoning. Attack stages inject log spikes across multiple relevant sources simultaneously.

---

## ARCHITECTURE

```
app.py (single file, ~700 lines)
├── SQLite DB (auto-created: nullgrids.db)
├── Background Thread: log engine (9 streams, 2-5s intervals)
├── Background Thread: SIGMA engine (10 rules, 10s intervals)
├── Flask Routes (20+)
│   ├── Company Frontend (/, /login, /dashboard, etc.)
│   ├── Red Team Vectors (/search, /profile, /upload, /employee, /admin, /financials)
│   ├── SOC API (/api/soc/logs, /breach, /attack_chain, /sigma_triggers, /packets, /ip_tags)
│   ├── DFIR (/dfir, /api/dfir/evidence, /action, /timeline)
│   └── GRC (/grc/dashboard, /mentor, /api/grc/controls, /gap_analysis, /risk_register)
└── Templates (15 HTML files)
```

---

## FILE STRUCTURE

```
nullgrids/
├── app.py              ← Main application (run this)
├── requirements.txt    ← Flask only
├── README.md           ← This file
├── nullgrids.db        ← Auto-created on first run
└── templates/
    ├── base.html
    ├── index.html          ← Company site
    ├── login.html          ← Red Team entry
    ├── dashboard.html      ← User panel
    ├── search.html         ← SQLi vector
    ├── profile.html        ← SSRF vector
    ├── upload.html         ← Upload + RCE
    ├── employee.html       ← IDOR detail
    ├── employee_list.html  ← IDOR list
    ├── admin.html          ← Admin console
    ├── financials.html     ← Exfil target
    ├── soc_monitor.html    ← SOC SIEM
    ├── dfir.html           ← DFIR portal
    ├── dfir_locked.html    ← DFIR gate
    ├── grc_dashboard.html  ← GRC system
    ├── grc_mentor.html     ← GRC evaluator
    └── error.html
```

---

## RUNNING IN COMPETITION

1. Host on a shared network (change `host="0.0.0.0"` already set in `app.py`)
2. Give teams their respective credentials
3. Teams access via `http://<server-ip>:5000`
4. SOC team watches `/soc/monitor` continuously
5. Use `/api/win_conditions` on a scoreboard screen
6. Mentor resets between rounds via `POST /mentor/reset`

---

## NOTES

- No external dependencies beyond Flask
- SQLite WAL mode enabled for concurrent access
- Threaded Flask server handles multiple teams simultaneously
- All "attacks" are simulated client-side — no real vulnerabilities exploited
- Designed for education and competition, not production deployment

---

*NullGrids Red vs Blue — Built for enterprise-grade cyber range training*
