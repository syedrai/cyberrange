#!/usr/bin/env python3
"""
NullGrids Red vs Blue — Enterprise Cyber Range
A full-featured cybersecurity competition platform
"""

import sqlite3, threading, time, random, hashlib, json, os, re, uuid
from datetime import datetime, timedelta
from flask import (Flask, render_template, request, redirect, url_for,
                   session, jsonify, g, make_response)
from functools import wraps

app = Flask(__name__)
app.secret_key = os.urandom(32)
DB_PATH = "nullgrids.db"

# ─── CONSTANTS ────────────────────────────────────────────────────────────────
ATTACK_STAGES = [
    {"id":1,  "name":"Brute Force Login",        "weight":5,  "log_types":["auth","alerts","firewall"]},
    {"id":2,  "name":"Basic Enumeration",         "weight":4,  "log_types":["access","webserver","ids"]},
    {"id":3,  "name":"SQL Injection",             "weight":8,  "log_types":["access","alerts","security","ids"]},
    {"id":4,  "name":"Credential Discovery",      "weight":7,  "log_types":["auth","security","endpoint"]},
    {"id":5,  "name":"IDOR Access Expansion",     "weight":6,  "log_types":["access","alerts","security"]},
    {"id":6,  "name":"SSRF Internal Mapping",     "weight":8,  "log_types":["webserver","firewall","ids"]},
    {"id":7,  "name":"Privilege Escalation",      "weight":10, "log_types":["auth","endpoint","security","alerts"]},
    {"id":8,  "name":"Admin Panel Access",        "weight":9,  "log_types":["access","auth","alerts"]},
    {"id":9,  "name":"File Upload / Webshell",    "weight":12, "log_types":["webserver","endpoint","alerts","ids"]},
    {"id":10, "name":"Remote Command Execution",  "weight":11, "log_types":["endpoint","syslog","alerts","security"]},
    {"id":11, "name":"Financial Data Access",     "weight":12, "log_types":["access","security","alerts"]},
    {"id":12, "name":"Data Exfiltration",         "weight":8,  "log_types":["firewall","ids","alerts","security"]},
]

LOG_SOURCES = ["access","alerts","webserver","auth","endpoint","ids","firewall","security","syslog"]

SIGMA_RULES = [
    {
        "id":"SIGMA-001","name":"Brute Force Authentication",
        "description":"Multiple failed login attempts from single IP",
        "severity":"HIGH","category":"auth",
        "pattern":r"FAILED.*login|authentication failure|invalid password",
        "threshold":5,"window":60,"stage":1
    },
    {
        "id":"SIGMA-002","name":"SQL Injection Attempt",
        "description":"SQL injection pattern detected in web request",
        "severity":"CRITICAL","category":"access",
        "pattern":r"UNION.*SELECT|' OR '|1=1|DROP TABLE|xp_cmdshell|SLEEP\(",
        "threshold":1,"window":10,"stage":3
    },
    {
        "id":"SIGMA-003","name":"IDOR Parameter Manipulation",
        "description":"Sequential or out-of-range ID parameter access",
        "severity":"MEDIUM","category":"access",
        "pattern":r"employee.*id=[0-9]+|user_id manipulation|IDOR",
        "threshold":3,"window":30,"stage":5
    },
    {
        "id":"SIGMA-004","name":"SSRF Internal Endpoint Probe",
        "description":"Server-Side Request Forgery attempt to internal network",
        "severity":"HIGH","category":"webserver",
        "pattern":r"SSRF|169\.254\.|192\.168\.|10\.\d+\.\d+|127\.0\.0",
        "threshold":1,"window":30,"stage":6
    },
    {
        "id":"SIGMA-005","name":"Privilege Escalation via Role Manipulation",
        "description":"Unexpected privilege or role change detected",
        "severity":"CRITICAL","category":"auth",
        "pattern":r"privilege escalation|role.*admin|sudo|elevated.*access",
        "threshold":1,"window":10,"stage":7
    },
    {
        "id":"SIGMA-006","name":"Suspicious File Upload",
        "description":"Potentially malicious file uploaded (PHP/JSP/ASPX shell)",
        "severity":"CRITICAL","category":"webserver",
        "pattern":r"\.php|\.jsp|\.aspx|webshell|cmd=|shell_exec|eval\(",
        "threshold":1,"window":5,"stage":9
    },
    {
        "id":"SIGMA-007","name":"Remote Command Execution",
        "description":"Command execution pattern from web process",
        "severity":"CRITICAL","category":"endpoint",
        "pattern":r"cmd\.exe|/bin/sh|whoami|net user|id;|RCE|command injection",
        "threshold":1,"window":5,"stage":10
    },
    {
        "id":"SIGMA-008","name":"Sensitive Data Exfiltration",
        "description":"Large volume data transfer or financial data access",
        "severity":"CRITICAL","category":"firewall",
        "pattern":r"exfil|large.*transfer|financial.*export|data.*dump|bytes_out>[0-9]{6}",
        "threshold":1,"window":10,"stage":12
    },
    {
        "id":"SIGMA-009","name":"Admin Panel Unauthorized Access",
        "description":"Access to administrative interface by non-admin account",
        "severity":"HIGH","category":"access",
        "pattern":r"/admin.*unauthorized|admin panel.*access|privilege.*admin",
        "threshold":1,"window":10,"stage":8
    },
    {
        "id":"SIGMA-010","name":"Lateral Movement - Internal Recon",
        "description":"Internal network scanning or service enumeration",
        "severity":"HIGH","category":"ids",
        "pattern":r"port scan|nmap|internal.*scan|enumeration|recon",
        "threshold":2,"window":60,"stage":2
    },
]

FAKE_EMPLOYEES = [
    ("alice.chen","alice@meridiantech.com","Finance","192.168.1.101"),
    ("bob.harris","bob@meridiantech.com","IT","192.168.1.102"),
    ("carol.james","carol@meridiantech.com","HR","192.168.1.103"),
    ("david.kim","david@meridiantech.com","Engineering","192.168.1.104"),
    ("eve.martin","eve@meridiantech.com","Legal","192.168.1.105"),
    ("frank.nguyen","frank@meridiantech.com","Finance","192.168.1.106"),
    ("grace.obi","grace@meridiantech.com","Management","192.168.1.107"),
    ("henry.park","henry@meridiantech.com","IT","192.168.1.108"),
]

ATTACKER_IPS = ["45.33.32.156","198.51.100.42","203.0.113.77","185.220.101.33","91.108.4.18"]

# ─── DATABASE ─────────────────────────────────────────────────────────────────
def get_db():
    if "db" not in g:
        g.db = sqlite3.connect(DB_PATH, timeout=10)
        g.db.row_factory = sqlite3.Row
        g.db.execute("PRAGMA journal_mode=WAL")
    return g.db

@app.teardown_appcontext
def close_db(e=None):
    db = g.pop("db", None)
    if db: db.close()

def init_db():
    conn = sqlite3.connect(DB_PATH)
    conn.execute("PRAGMA journal_mode=WAL")
    c = conn.cursor()

    c.executescript("""
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE NOT NULL,
        password TEXT NOT NULL,
        role TEXT DEFAULT 'user',
        email TEXT,
        department TEXT,
        ip TEXT,
        active INTEGER DEFAULT 1,
        sessions_revoked INTEGER DEFAULT 0,
        created_at TEXT DEFAULT CURRENT_TIMESTAMP
    );
    CREATE TABLE IF NOT EXISTS logs (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        source TEXT NOT NULL,
        level TEXT NOT NULL,
        message TEXT NOT NULL,
        ip TEXT,
        username TEXT,
        stage_triggered INTEGER DEFAULT 0,
        chain_id TEXT,
        incident_id TEXT,
        sigma_rule TEXT,
        ts TEXT DEFAULT CURRENT_TIMESTAMP
    );
    CREATE TABLE IF NOT EXISTS breach_state (
        id INTEGER PRIMARY KEY DEFAULT 1,
        breach_pct REAL DEFAULT 0,
        current_stage INTEGER DEFAULT 0,
        dfir_unlocked INTEGER DEFAULT 0,
        soc_escalated INTEGER DEFAULT 0,
        red_ip TEXT DEFAULT '',
        chain_id TEXT DEFAULT '',
        started_at TEXT DEFAULT CURRENT_TIMESTAMP
    );
    CREATE TABLE IF NOT EXISTS attack_chain (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        stage_id INTEGER,
        stage_name TEXT,
        incident_id TEXT,
        chain_id TEXT,
        status TEXT DEFAULT 'detected',
        attacker_ip TEXT,
        ts TEXT DEFAULT CURRENT_TIMESTAMP
    );
    CREATE TABLE IF NOT EXISTS ip_tags (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        ip TEXT UNIQUE,
        tag TEXT,
        username TEXT,
        blocked INTEGER DEFAULT 0,
        note TEXT,
        ts TEXT DEFAULT CURRENT_TIMESTAMP
    );
    CREATE TABLE IF NOT EXISTS sigma_triggers (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        rule_id TEXT,
        rule_name TEXT,
        severity TEXT,
        ip TEXT,
        log_id INTEGER,
        ts TEXT DEFAULT CURRENT_TIMESTAMP
    );
    CREATE TABLE IF NOT EXISTS dfir_actions (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        action TEXT,
        target TEXT,
        performed_by TEXT,
        result TEXT,
        ts TEXT DEFAULT CURRENT_TIMESTAMP
    );
    CREATE TABLE IF NOT EXISTS grc_submissions (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        team TEXT,
        control TEXT,
        status TEXT,
        evidence TEXT,
        score REAL DEFAULT 0,
        ts TEXT DEFAULT CURRENT_TIMESTAMP
    );
    CREATE TABLE IF NOT EXISTS packets (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        src_ip TEXT, dst_ip TEXT,
        src_port INTEGER, dst_port INTEGER,
        protocol TEXT, size INTEGER,
        payload TEXT, stage_id INTEGER,
        ts TEXT DEFAULT CURRENT_TIMESTAMP
    );
    CREATE TABLE IF NOT EXISTS employees (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT, email TEXT,
        department TEXT, ip TEXT,
        salary REAL, ssn TEXT,
        notes TEXT
    );
    CREATE TABLE IF NOT EXISTS financials (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        account TEXT, amount REAL,
        description TEXT, classification TEXT
    );
    """)

    # Seed users
    def pw(p): return hashlib.sha256(p.encode()).hexdigest()
    users = [
        ("admin","admin123","admin","admin@meridiantech.com","IT","192.168.1.1"),
        ("jdoe","password123","user","jdoe@meridiantech.com","Finance","192.168.1.50"),
        ("soc_analyst","SOCpass2024!","soc","soc@meridiantech.com","Security","192.168.1.10"),
        ("dfir_lead","DFIRpass2024!","dfir","dfir@meridiantech.com","Security","192.168.1.11"),
        ("grc_manager","GRCpass2024!","grc","grc@meridiantech.com","Compliance","192.168.1.12"),
    ]
    for u in users:
        try:
            c.execute("INSERT INTO users(username,password,role,email,department,ip) VALUES(?,?,?,?,?,?)",
                      (u[0], pw(u[1]), u[2], u[3], u[4], u[5]))
        except: pass

    # Seed employees
    for emp in FAKE_EMPLOYEES:
        try:
            c.execute("INSERT INTO employees(username,email,department,ip,salary,ssn,notes) VALUES(?,?,?,?,?,?,?)",
                      (emp[0],emp[1],emp[2],emp[3],
                       round(random.uniform(60000,180000),2),
                       f"{random.randint(100,999)}-{random.randint(10,99)}-{random.randint(1000,9999)}",
                       "Standard employee record"))
        except: pass

    # Seed financials
    accounts = [
        ("ACC-001-EXEC",4200000,"Executive Reserve Fund","CONFIDENTIAL"),
        ("ACC-002-OPS",890000,"Operations Budget","INTERNAL"),
        ("ACC-003-RD",2100000,"R&D Allocation","RESTRICTED"),
        ("ACC-004-PAYROLL",7800000,"Payroll Account","CONFIDENTIAL"),
        ("ACC-005-VENDOR",340000,"Vendor Payments","INTERNAL"),
    ]
    for acc in accounts:
        try:
            c.execute("INSERT INTO financials(account,amount,description,classification) VALUES(?,?,?,?)", acc)
        except: pass

    # Seed breach state
    c.execute("INSERT OR IGNORE INTO breach_state(id,breach_pct,current_stage,chain_id) VALUES(1,0,0,?)",
              (str(uuid.uuid4())[:8],))

    conn.commit()
    conn.close()
    print("[✓] Database initialized")

# ─── AUTH HELPERS ──────────────────────────────────────────────────────────────
def login_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if "user" not in session:
            return redirect(url_for("login"))
        return f(*args, **kwargs)
    return decorated

def role_required(*roles):
    def decorator(f):
        @wraps(f)
        def decorated(*args, **kwargs):
            if "user" not in session:
                return redirect(url_for("login"))
            if session.get("role") not in roles:
                return render_template("error.html", msg="Access Denied — Insufficient Privileges"), 403
            return f(*args, **kwargs)
        return decorated
    return decorator

# ─── LOG ENGINE ───────────────────────────────────────────────────────────────
_log_lock = threading.Lock()

def write_log(source, level, message, ip=None, username=None,
              stage=0, chain_id=None, incident_id=None, sigma_rule=None):
    with _log_lock:
        try:
            conn = sqlite3.connect(DB_PATH, timeout=5)
            conn.execute("PRAGMA journal_mode=WAL")
            ts = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S")
            conn.execute(
                "INSERT INTO logs(source,level,message,ip,username,stage_triggered,chain_id,incident_id,sigma_rule,ts)"
                " VALUES(?,?,?,?,?,?,?,?,?,?)",
                (source, level, message, ip, username, stage, chain_id, incident_id, sigma_rule, ts)
            )
            conn.commit()
            conn.close()
        except Exception as e:
            print(f"[LOG ERROR] {e}")

def get_breach():
    conn = sqlite3.connect(DB_PATH, timeout=5)
    conn.row_factory = sqlite3.Row
    row = conn.execute("SELECT * FROM breach_state WHERE id=1").fetchone()
    conn.close()
    return dict(row) if row else {}

def update_breach(pct_delta=0, stage=None, dfir=None, soc_esc=None, red_ip=None):
    conn = sqlite3.connect(DB_PATH, timeout=5)
    conn.execute("PRAGMA journal_mode=WAL")
    cur = conn.execute("SELECT * FROM breach_state WHERE id=1").fetchone()
    if not cur:
        conn.close(); return
    new_pct = min(100, max(0, cur["breach_pct"] + pct_delta))
    new_stage = stage if stage is not None else cur["current_stage"]
    new_dfir = dfir if dfir is not None else cur["dfir_unlocked"]
    new_soc = soc_esc if soc_esc is not None else cur["soc_escalated"]
    new_ip = red_ip if red_ip is not None else cur["red_ip"]
    if new_pct >= 60 and new_soc:
        new_dfir = 1
    conn.execute(
        "UPDATE breach_state SET breach_pct=?,current_stage=?,dfir_unlocked=?,soc_escalated=?,red_ip=? WHERE id=1",
        (new_pct, new_stage, new_dfir, new_soc, new_ip)
    )
    conn.commit()
    conn.close()

def log_attack_chain(stage_id, stage_name, attacker_ip, status="detected"):
    breach = get_breach()
    chain_id = breach.get("chain_id", str(uuid.uuid4())[:8])
    incident_id = f"INC-{datetime.utcnow().strftime('%Y%m%d')}-{random.randint(1000,9999)}"
    conn = sqlite3.connect(DB_PATH, timeout=5)
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute(
        "INSERT INTO attack_chain(stage_id,stage_name,incident_id,chain_id,status,attacker_ip,ts) VALUES(?,?,?,?,?,?,?)",
        (stage_id, stage_name, incident_id, chain_id, status,
         attacker_ip, datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S"))
    )
    conn.commit()
    conn.close()
    return incident_id, chain_id

# ─── BACKGROUND LOG SIMULATOR ─────────────────────────────────────────────────
def background_log_engine():
    """Continuous background simulation of normal + attack traffic"""
    normal_msgs = {
        "access":   ["GET /index.html 200","GET /about 200","POST /api/data 200","GET /css/main.css 304","GET /js/app.js 200"],
        "auth":     ["Successful login: alice.chen from 192.168.1.101","Session created for bob.harris","Token refreshed for carol.james","Password policy check passed","2FA verified for grace.obi"],
        "webserver":["Request processed in 23ms","Static asset served","Cache hit for /api/config","Connection from 192.168.1.104","Keep-alive timeout"],
        "endpoint": ["Antivirus scan completed — clean","Software update applied","Disk usage 67%","Process monitor healthy","CPU load normal"],
        "firewall": ["Outbound allowed: 192.168.1.101 → 8.8.8.8:443","Inbound allowed: 0.0.0.0 → 80","Policy rule 12 matched","Connection state ESTABLISHED","Packet forwarded"],
        "ids":      ["Baseline traffic nominal","Signature database updated","No anomalies detected","Packet inspection complete","Flow analysis normal"],
        "security": ["Compliance scan scheduled","Certificate expiry check OK","Vulnerability assessment queued","Access review completed","Audit log archived"],
        "syslog":   ["System time synchronized","Cron job executed: backup","Memory usage 42%","Kernel update check OK","Daemon restarted: nginx"],
        "alerts":   ["INFO: Scheduled maintenance window","INFO: Backup completed successfully","INFO: Health check passed","INFO: Certificate renewal","INFO: User provisioning completed"],
    }
    false_positives = [
        ("ids","MEDIUM","Possible port scan — 192.168.1.104 — RESOLVED: Authorized vulnerability scan"),
        ("alerts","HIGH","Unusual login time alice.chen 22:14 — RESOLVED: Authorized overtime"),
        ("firewall","MEDIUM","High outbound bytes frank.nguyen — RESOLVED: Authorized data export"),
        ("auth","MEDIUM","Multiple login attempts bob.harris — RESOLVED: Password manager retry"),
    ]
    while True:
        try:
            for source in LOG_SOURCES:
                if random.random() < 0.6:
                    msg = random.choice(normal_msgs.get(source, ["System event"]))
                    ip = random.choice([e[3] for e in FAKE_EMPLOYEES])
                    write_log(source, "INFO", msg, ip=ip)
            if random.random() < 0.08:
                fp = random.choice(false_positives)
                write_log(fp[0], fp[1], fp[2], ip=random.choice([e[3] for e in FAKE_EMPLOYEES]))
            # Simulate packets
            _gen_background_packets()
            time.sleep(random.uniform(2,5))
        except Exception as e:
            print(f"[BG ENGINE] {e}")
            time.sleep(5)

def _gen_background_packets():
    try:
        internal_ips = [e[3] for e in FAKE_EMPLOYEES]
        src = random.choice(internal_ips)
        dst = random.choice(["8.8.8.8","1.1.1.1","10.0.0.1","192.168.1.1"])
        proto = random.choice(["TCP","UDP","HTTP","HTTPS","DNS"])
        conn = sqlite3.connect(DB_PATH, timeout=3)
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute(
            "INSERT INTO packets(src_ip,dst_ip,src_port,dst_port,protocol,size,payload,stage_id,ts) VALUES(?,?,?,?,?,?,?,?,?)",
            (src, dst, random.randint(1024,65535), random.choice([80,443,53,22,8080]),
             proto, random.randint(64,1500), f"Normal {proto} traffic", 0,
             datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S"))
        )
        conn.commit()
        conn.close()
    except: pass

def sigma_detection_engine():
    """Run SIGMA rules against recent logs every 10 seconds"""
    while True:
        time.sleep(10)
        try:
            conn = sqlite3.connect(DB_PATH, timeout=5)
            conn.row_factory = sqlite3.Row
            cutoff = (datetime.utcnow() - timedelta(minutes=5)).strftime("%Y-%m-%d %H:%M:%S")
            recent = conn.execute("SELECT * FROM logs WHERE ts > ?", (cutoff,)).fetchall()
            for rule in SIGMA_RULES:
                pattern = re.compile(rule["pattern"], re.IGNORECASE)
                matches = [r for r in recent if r["source"] == rule["category"] and pattern.search(r["message"])]
                if len(matches) >= rule["threshold"]:
                    for m in matches[:1]:
                        existing = conn.execute(
                            "SELECT id FROM sigma_triggers WHERE rule_id=? AND log_id=?",
                            (rule["id"], m["id"])
                        ).fetchone()
                        if not existing:
                            conn.execute(
                                "INSERT INTO sigma_triggers(rule_id,rule_name,severity,ip,log_id,ts) VALUES(?,?,?,?,?,?)",
                                (rule["id"], rule["name"], rule["severity"], m["ip"], m["id"],
                                 datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S"))
                            )
                            conn.commit()
            conn.close()
        except Exception as e:
            print(f"[SIGMA] {e}")

# ─── ATTACK SIMULATION HELPERS ────────────────────────────────────────────────
def simulate_attack_logs(stage_id, attacker_ip, username=None):
    s = next((s for s in ATTACK_STAGES if s["id"]==stage_id), None)
    if not s: return
    stage_logs = {
        1: [("auth","HIGH",f"FAILED login attempt from {attacker_ip} — user: admin"),
            ("auth","HIGH",f"FAILED login attempt from {attacker_ip} — user: jdoe"),
            ("auth","CRITICAL",f"Brute force detected: {attacker_ip} — 47 attempts in 30s"),
            ("firewall","HIGH",f"Rate limit triggered: {attacker_ip} blocked temporarily"),
            ("alerts","HIGH",f"ALERT: Brute force lockout triggered for {attacker_ip}"),
            ("ids","HIGH",f"IDS ALERT: Authentication brute force — {attacker_ip}")],
        2: [("access","MEDIUM",f"GET /dashboard HTTP/1.1 200 — {attacker_ip}"),
            ("access","MEDIUM",f"GET /admin HTTP/1.1 403 — {attacker_ip}"),
            ("access","LOW",f"GET /robots.txt HTTP/1.1 200 — {attacker_ip}"),
            ("ids","MEDIUM",f"Enumeration pattern: {attacker_ip} scanning directory structure"),
            ("webserver","MEDIUM",f"404 spike: {attacker_ip} — 23 not-found in 10s")],
        3: [("access","CRITICAL",f"SQLi: GET /search?q=' OR '1'='1 — {attacker_ip}"),
            ("access","CRITICAL",f"SQLi: UNION SELECT username,password FROM users — {attacker_ip}"),
            ("alerts","CRITICAL",f"SQL INJECTION DETECTED: {attacker_ip} — payload: UNION SELECT"),
            ("ids","CRITICAL",f"IDS: SQL injection signature match — {attacker_ip}"),
            ("security","CRITICAL",f"Database query anomaly: unexpected UNION clause — {attacker_ip}"),
            ("webserver","HIGH",f"WAF bypass attempt: encoded SQLi payload — {attacker_ip}")],
        4: [("security","CRITICAL",f"Credentials extracted via SQLi: hashed passwords exposed — {attacker_ip}"),
            ("auth","CRITICAL",f"Credential dump: 5 user hashes obtained from DB — {attacker_ip}"),
            ("alerts","CRITICAL",f"ALERT: Password hash exfiltration detected in SQL response")],
        5: [("access","HIGH",f"IDOR: GET /employee?id=1 through id=47 — {attacker_ip}"),
            ("alerts","HIGH",f"IDOR pattern: sequential ID enumeration by {attacker_ip}"),
            ("security","HIGH",f"Unauthorized employee record access — {attacker_ip}"),
            ("ids","HIGH",f"Parameter manipulation detected: /employee endpoint — {attacker_ip}")],
        6: [("webserver","CRITICAL",f"SSRF: POST /profile url=http://169.254.169.254/metadata — {attacker_ip}"),
            ("firewall","CRITICAL",f"Internal request from webserver to 169.254.169.254 — SSRF"),
            ("ids","CRITICAL",f"SSRF detected: metadata endpoint probe by {attacker_ip}"),
            ("alerts","CRITICAL",f"ALERT: Cloud metadata service accessed via SSRF — {attacker_ip}"),
            ("security","HIGH",f"Internal network mapping via SSRF: 192.168.1.0/24 probed")],
        7: [("auth","CRITICAL",f"Privilege escalation: jdoe → admin role manipulation — {attacker_ip}"),
            ("endpoint","CRITICAL",f"Unauthorized sudo execution: www-data on web server — {attacker_ip}"),
            ("security","CRITICAL",f"Role elevation detected: standard user assigned admin rights"),
            ("alerts","CRITICAL",f"ALERT: Privilege escalation chain confirmed — {attacker_ip}")],
        8: [("access","CRITICAL",f"Admin panel accessed: /admin by {attacker_ip} with escalated token"),
            ("auth","CRITICAL",f"Admin session established: unauthorized user — {attacker_ip}"),
            ("alerts","CRITICAL",f"ALERT: Admin console breach — {attacker_ip}"),
            ("security","CRITICAL",f"Admin panel accessed — full system visibility obtained")],
        9: [("webserver","CRITICAL",f"File upload: shell.php uploaded via /upload — {attacker_ip}"),
            ("endpoint","CRITICAL",f"Webshell detected: /uploads/shell.php — suspicious process spawn"),
            ("ids","CRITICAL",f"IDS: PHP webshell signature detected — {attacker_ip}"),
            ("alerts","CRITICAL",f"ALERT: Webshell deployment confirmed on web server"),
            ("security","CRITICAL",f"Malicious file upload: shell.php — AV signature match")],
        10:[("endpoint","CRITICAL",f"RCE: shell.php?cmd=whoami → www-data — {attacker_ip}"),
            ("endpoint","CRITICAL",f"RCE: shell.php?cmd=id;uname -a — {attacker_ip}"),
            ("syslog","CRITICAL",f"Unexpected process: /bin/bash spawned by nginx — {attacker_ip}"),
            ("alerts","CRITICAL",f"ALERT: Remote command execution confirmed — full shell access"),
            ("security","CRITICAL",f"System compromise: attacker has interactive shell access")],
        11:[("access","CRITICAL",f"Financial data accessed: /financials — {attacker_ip}"),
            ("security","CRITICAL",f"Restricted data exposure: ACC-001-EXEC $4.2M account — {attacker_ip}"),
            ("alerts","CRITICAL",f"ALERT: Confidential financial records accessed — {attacker_ip}"),
            ("ids","CRITICAL",f"Sensitive data accessed: financial classification breach")],
        12:[("firewall","CRITICAL",f"Large outbound transfer: {attacker_ip} → 45.33.32.156 — 47.3MB"),
            ("ids","CRITICAL",f"Data exfiltration: sustained outbound stream to C2 server"),
            ("alerts","CRITICAL",f"ALERT: DATA EXFILTRATION IN PROGRESS — {attacker_ip}"),
            ("security","CRITICAL",f"BREACH COMPLETE: Full data exfiltration detected — incident declared"),
            ("firewall","CRITICAL",f"C2 beacon: {attacker_ip} → 45.33.32.156:443 — encrypted channel")],
    }
    logs = stage_logs.get(stage_id, [])
    incident_id, chain_id = log_attack_chain(stage_id, s["name"], attacker_ip)
    for src, lvl, msg in logs:
        write_log(src, lvl, msg, ip=attacker_ip, username=username,
                  stage=stage_id, chain_id=chain_id, incident_id=incident_id)
    # Simulate attack packets
    _gen_attack_packets(stage_id, attacker_ip)
    return incident_id, chain_id

def _gen_attack_packets(stage_id, attacker_ip):
    payloads = {
        1: "POST /login username=admin&password=admin123",
        3: "GET /search?q=%27+OR+%271%27%3D%271 HTTP/1.1",
        6: "POST /profile url=http://169.254.169.254/latest/meta-data/",
        9: "POST /upload Content-Disposition: filename=shell.php",
        12: "TCP DATA 47301829 bytes → 45.33.32.156:443",
    }
    payload = payloads.get(stage_id, f"Stage {stage_id} attack traffic")
    try:
        conn = sqlite3.connect(DB_PATH, timeout=3)
        conn.execute("PRAGMA journal_mode=WAL")
        for _ in range(random.randint(3,8)):
            conn.execute(
                "INSERT INTO packets(src_ip,dst_ip,src_port,dst_port,protocol,size,payload,stage_id,ts) VALUES(?,?,?,?,?,?,?,?,?)",
                (attacker_ip, "192.168.1.1", random.randint(40000,60000), random.choice([80,443,8080]),
                 "TCP", random.randint(300,9000), payload, stage_id,
                 datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S"))
            )
        conn.commit()
        conn.close()
    except: pass

# ─── ROUTES: COMPANY FRONTEND ──────────────────────────────────────────────────
@app.route("/")
def index():
    write_log("access","INFO",f"GET / 200",ip=request.remote_addr)
    return render_template("index.html")

@app.route("/login", methods=["GET","POST"])
def login():
    error = None
    ip = request.remote_addr

    if request.method == "POST":
        username = request.form.get("username","").strip()
        password = request.form.get("password","")
        pw_hash = hashlib.sha256(password.encode()).hexdigest()

        db = get_db()
        user = db.execute("SELECT * FROM users WHERE username=? AND active=1", (username,)).fetchone()

        if not user or user["password"] != pw_hash:
            write_log("auth","HIGH",f"FAILED login attempt from {ip} — user: {username}",ip=ip,username=username)
            # Detect brute force
            conn2 = sqlite3.connect(DB_PATH, timeout=5)
            cutoff = (datetime.utcnow()-timedelta(seconds=30)).strftime("%Y-%m-%d %H:%M:%S")
            fails = conn2.execute("SELECT COUNT(*) FROM logs WHERE ip=? AND level='HIGH' AND source='auth' AND ts>?",
                                  (ip,cutoff)).fetchone()[0]
            conn2.close()
            if fails >= 4:
                breach = get_breach()
                if breach.get("current_stage",0) < 1:
                    simulate_attack_logs(1, ip, username)
                    update_breach(pct_delta=5, stage=1, red_ip=ip)
            error = "Invalid credentials"
        else:
            if user["sessions_revoked"]:
                write_log("auth","CRITICAL",f"Login attempt on revoked account: {username} — {ip}",ip=ip)
                error = "Account suspended. Contact IT Security."
            else:
                session["user"] = username
                session["role"] = user["role"]
                session["uid"]  = user["id"]
                write_log("auth","INFO",f"Successful login: {username} from {ip}",ip=ip,username=username)
                if user["role"] in ("soc",):
                    return redirect(url_for("soc_monitor"))
                elif user["role"] in ("dfir",):
                    return redirect(url_for("dfir_portal"))
                elif user["role"] in ("grc",):
                    return redirect(url_for("grc_dashboard"))
                else:
                    return redirect(url_for("dashboard"))

    return render_template("login.html", error=error)

@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("index"))

@app.route("/dashboard")
@login_required
def dashboard():
    breach = get_breach()
    write_log("access","INFO",f"GET /dashboard 200",ip=request.remote_addr,username=session.get("user"))
    return render_template("dashboard.html", breach=breach)

@app.route("/search")
@login_required
def search():
    ip = request.remote_addr
    q = request.args.get("q","")
    results = []
    error = None

    if q:
        write_log("access","INFO",f"GET /search?q={q[:80]} 200",ip=ip,username=session.get("user"))
        # Intentionally vulnerable SQLi simulation
        sqli_patterns = ["union","select","'","--","or 1","sleep(","xp_cmd","drop table"]
        is_sqli = any(p in q.lower() for p in sqli_patterns)
        if is_sqli:
            breach = get_breach()
            if breach.get("current_stage",0) < 3:
                simulate_attack_logs(3, ip, session.get("user"))
                update_breach(pct_delta=8, stage=3, red_ip=ip)
            # Return fake "leaked" data
            results = [
                {"type":"user","data":"jdoe | 5f4dcc3b5aa765d61d8327deb882cf99 | Finance"},
                {"type":"user","data":"admin | 0192023a7bbd73250516f069df18b500 | IT"},
                {"type":"user","data":"carol.james | 827ccb0eea8a706c4c34a16891f84e7b | HR"},
            ]
            write_log("security","CRITICAL",f"SQLi data extracted: credentials exposed — {ip}",
                      ip=ip,username=session.get("user"),stage=3)
        else:
            # Normal search
            db = get_db()
            try:
                rows = db.execute(f"SELECT username,email,department FROM users WHERE username LIKE ?",
                                  (f"%{q}%",)).fetchall()
                results = [{"type":"user","data":f"{r['username']} | {r['email']} | {r['department']}"} for r in rows]
            except Exception as e:
                error = str(e)

    return render_template("search.html", q=q, results=results, error=error)

@app.route("/profile", methods=["GET","POST"])
@login_required
def profile():
    ip = request.remote_addr
    ssrf_result = None
    if request.method == "POST":
        url = request.form.get("url","")
        write_log("webserver","HIGH",f"POST /profile url={url} — {ip}",ip=ip,username=session.get("user"))
        # SSRF detection
        ssrf_indicators = ["169.254","192.168","10.","127.0","localhost","metadata","internal","file://"]
        if any(s in url.lower() for s in ssrf_indicators):
            breach = get_breach()
            if breach.get("current_stage",0) < 6:
                simulate_attack_logs(6, ip, session.get("user"))
                update_breach(pct_delta=8, stage=6, red_ip=ip)
            # Fake internal response
            ssrf_result = {
                "url": url,
                "response": '{"instanceId":"i-0abc123def","region":"us-east-1","iam":{"role":"EC2-WebServer-Role"},"privateIp":"10.0.1.45","publicIp":"203.0.113.100"}'
            }
        else:
            ssrf_result = {"url": url, "response": "Connection refused or DNS resolution failed"}

    db = get_db()
    user = db.execute("SELECT * FROM users WHERE username=?", (session["user"],)).fetchone()
    return render_template("profile.html", user=user, ssrf_result=ssrf_result)

@app.route("/upload", methods=["GET","POST"])
@login_required
def upload():
    ip = request.remote_addr
    rce_result = None
    upload_result = None

    if request.method == "POST":
        if "file" in request.files:
            f = request.files["file"]
            filename = f.filename
            write_log("webserver","HIGH",f"File upload: {filename} from {ip}",ip=ip,username=session.get("user"))
            shell_exts = [".php",".jsp",".aspx",".phtml",".php5",".shtml"]
            if any(filename.lower().endswith(e) for e in shell_exts):
                breach = get_breach()
                if breach.get("current_stage",0) < 9:
                    simulate_attack_logs(9, ip, session.get("user"))
                    update_breach(pct_delta=12, stage=9, red_ip=ip)
                upload_result = {"filename": filename, "path": f"/uploads/{filename}", "status":"uploaded"}
            else:
                upload_result = {"filename": filename, "path": f"/uploads/{filename}", "status":"uploaded"}

        cmd = request.form.get("cmd","")
        if cmd:
            write_log("endpoint","CRITICAL",f"RCE: cmd={cmd[:100]} from {ip}",ip=ip,username=session.get("user"),stage=10)
            breach = get_breach()
            if breach.get("current_stage",0) < 10:
                simulate_attack_logs(10, ip, session.get("user"))
                update_breach(pct_delta=11, stage=10, red_ip=ip)
            fake_outputs = {
                "whoami": "www-data",
                "id": "uid=33(www-data) gid=33(www-data) groups=33(www-data)",
                "uname -a": "Linux meridian-web01 5.15.0-91-generic #101-Ubuntu SMP x86_64 GNU/Linux",
                "ls /": "bin boot dev etc home lib media mnt opt proc root run srv sys tmp usr var",
                "cat /etc/passwd": "root:x:0:0:root:/root:/bin/bash\nwww-data:x:33:33:www-data:/var/www:/usr/sbin/nologin",
                "ifconfig": "eth0: 10.0.1.45 netmask 255.255.255.0\nlo: 127.0.0.1",
            }
            rce_result = fake_outputs.get(cmd.strip(), f"sh: 1: {cmd}: not found")

    return render_template("upload.html", upload_result=upload_result, rce_result=rce_result)

@app.route("/employee")
@login_required
def employee():
    ip = request.remote_addr
    eid = request.args.get("id", type=int)
    db = get_db()
    breach = get_breach()

    if eid:
        write_log("access","MEDIUM",f"GET /employee?id={eid} — {ip}",ip=ip,username=session.get("user"))
        # IDOR: any id works
        all_ids = [r["id"] for r in db.execute("SELECT id FROM employees").fetchall()]
        if eid not in all_ids:
            # Sequential enumeration detected
            if breach.get("current_stage",0) < 5:
                simulate_attack_logs(5, ip, session.get("user"))
                update_breach(pct_delta=6, stage=5, red_ip=ip)
        emp = db.execute("SELECT * FROM employees WHERE id=?", (eid,)).fetchone()
        if breach.get("current_stage",0) < 5 and emp:
            update_breach(pct_delta=3, stage=5, red_ip=ip)
        return render_template("employee.html", emp=emp, eid=eid)
    else:
        emps = db.execute("SELECT id,username,department FROM employees").fetchall()
        return render_template("employee_list.html", emps=emps)

@app.route("/admin")
@login_required
def admin():
    ip = request.remote_addr
    breach = get_breach()
    db = get_db()

    if session.get("role") != "admin":
        write_log("access","CRITICAL",f"Unauthorized /admin access attempt — {ip}",
                  ip=ip,username=session.get("user"),stage=8)
        if breach.get("current_stage",0) < 8:
            simulate_attack_logs(8, ip, session.get("user"))
            update_breach(pct_delta=9, stage=8, red_ip=ip)
        # Privilege escalation path
        if breach.get("current_stage",0) >= 7:
            # Allow access after escalation
            pass
        else:
            return render_template("error.html", msg="403 — Forbidden. Access logged."), 403

    write_log("access","INFO",f"Admin panel accessed — {ip}",ip=ip,username=session.get("user"),stage=8)
    users = db.execute("SELECT id,username,role,email,department,active FROM users").fetchall()
    return render_template("admin.html", users=users, breach=breach)

@app.route("/financials")
@login_required
def financials():
    ip = request.remote_addr
    breach = get_breach()
    db = get_db()

    write_log("access","HIGH",f"GET /financials — {ip}",ip=ip,username=session.get("user"))
    if breach.get("current_stage",0) < 11:
        simulate_attack_logs(11, ip, session.get("user"))
        update_breach(pct_delta=12, stage=11, red_ip=ip)

    data = db.execute("SELECT * FROM financials").fetchall()
    return render_template("financials.html", data=data)

@app.route("/exfil", methods=["POST"])
@login_required
def exfil():
    ip = request.remote_addr
    breach = get_breach()
    if breach.get("current_stage",0) < 12:
        simulate_attack_logs(12, ip, session.get("user"))
        update_breach(pct_delta=8, stage=12, red_ip=ip)
    write_log("security","CRITICAL",f"DATA EXFILTRATION EXECUTED — {ip}",
              ip=ip,username=session.get("user"),stage=12)
    return jsonify({"status":"exfiltrated","bytes":49283747,"destination":"45.33.32.156","files":["financials_dump.csv","employees_pii.json","admin_credentials.txt"]})

# ─── SOC ROUTES ───────────────────────────────────────────────────────────────
@app.route("/soc/monitor")
@role_required("soc","admin")
def soc_monitor():
    return render_template("soc_monitor.html")

@app.route("/api/soc/logs")
@role_required("soc","admin")
def api_soc_logs():
    source = request.args.get("source","")
    level  = request.args.get("level","")
    ip_f   = request.args.get("ip","")
    search = request.args.get("search","")
    limit  = int(request.args.get("limit",200))

    db = get_db()
    query = "SELECT * FROM logs WHERE 1=1"
    params = []
    if source: query += " AND source=?"; params.append(source)
    if level:  query += " AND level=?";  params.append(level)
    if ip_f:   query += " AND ip LIKE ?"; params.append(f"%{ip_f}%")
    if search: query += " AND message LIKE ?"; params.append(f"%{search}%")
    query += " ORDER BY ts DESC LIMIT ?"
    params.append(limit)

    rows = db.execute(query, params).fetchall()
    return jsonify([dict(r) for r in rows])

@app.route("/api/soc/breach")
def api_breach():
    return jsonify(get_breach())

@app.route("/api/soc/attack_chain")
@role_required("soc","admin","dfir")
def api_attack_chain():
    db = get_db()
    rows = db.execute("SELECT * FROM attack_chain ORDER BY ts DESC LIMIT 100").fetchall()
    return jsonify([dict(r) for r in rows])

@app.route("/api/soc/sigma_triggers")
@role_required("soc","admin","dfir")
def api_sigma_triggers():
    db = get_db()
    rows = db.execute("SELECT * FROM sigma_triggers ORDER BY ts DESC LIMIT 100").fetchall()
    return jsonify([dict(r) for r in rows])

@app.route("/api/soc/packets")
@role_required("soc","admin","dfir")
def api_packets():
    db = get_db()
    stage_f = request.args.get("stage", type=int)
    if stage_f:
        rows = db.execute("SELECT * FROM packets WHERE stage_id=? ORDER BY ts DESC LIMIT 50",(stage_f,)).fetchall()
    else:
        rows = db.execute("SELECT * FROM packets ORDER BY ts DESC LIMIT 100").fetchall()
    return jsonify([dict(r) for r in rows])

@app.route("/api/soc/ip_tags", methods=["GET","POST"])
@role_required("soc","admin","dfir")
def api_ip_tags():
    db = get_db()
    if request.method == "POST":
        data = request.json or {}
        ip = data.get("ip","")
        tag = data.get("tag","suspicious")
        blocked = int(data.get("blocked",0))
        note = data.get("note","")
        username = data.get("username","")
        db.execute(
            "INSERT OR REPLACE INTO ip_tags(ip,tag,username,blocked,note,ts) VALUES(?,?,?,?,?,?)",
            (ip,tag,username,blocked,note,datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S"))
        )
        db.connection.commit()
        write_log("security","INFO",f"IP tagged: {ip} → {tag} (blocked={blocked}) by {session.get('user')}",
                  ip=ip)
        return jsonify({"status":"ok"})
    rows = db.execute("SELECT * FROM ip_tags ORDER BY ts DESC").fetchall()
    return jsonify([dict(r) for r in rows])

@app.route("/api/soc/escalate", methods=["POST"])
@role_required("soc","admin")
def api_escalate():
    update_breach(soc_esc=1)
    write_log("security","CRITICAL","SOC escalation triggered — DFIR team notified",
              username=session.get("user"))
    return jsonify({"status":"escalated","dfir_check": get_breach().get("dfir_unlocked",0)})

# ─── DFIR ROUTES ──────────────────────────────────────────────────────────────
@app.route("/dfir")
@role_required("dfir","admin")
def dfir_portal():
    breach = get_breach()
    if not breach.get("dfir_unlocked") and session.get("role") != "admin":
        return render_template("dfir_locked.html", breach=breach)
    db = get_db()
    actions = db.execute("SELECT * FROM dfir_actions ORDER BY ts DESC LIMIT 50").fetchall()
    return render_template("dfir.html", breach=breach, actions=actions)

@app.route("/api/dfir/evidence")
@role_required("dfir","admin")
def api_dfir_evidence():
    db = get_db()
    breach = get_breach()
    stage = breach.get("current_stage",0)
    # Evidence = attack-related logs
    logs = db.execute(
        "SELECT * FROM logs WHERE stage_triggered > 0 ORDER BY ts ASC LIMIT 500"
    ).fetchall()
    chain = db.execute("SELECT * FROM attack_chain ORDER BY ts ASC").fetchall()
    sigma = db.execute("SELECT * FROM sigma_triggers ORDER BY ts ASC").fetchall()
    packets = db.execute("SELECT * FROM packets WHERE stage_id > 0 ORDER BY ts ASC LIMIT 100").fetchall()
    return jsonify({
        "logs": [dict(r) for r in logs],
        "chain": [dict(r) for r in chain],
        "sigma": [dict(r) for r in sigma],
        "packets": [dict(r) for r in packets],
        "breach": dict(breach),
    })

@app.route("/api/dfir/action", methods=["POST"])
@role_required("dfir","admin")
def api_dfir_action():
    data = request.json or {}
    action = data.get("action","")
    target = data.get("target","")
    result = "Success"
    db = get_db()

    if action == "block_ip":
        db.execute("INSERT OR REPLACE INTO ip_tags(ip,tag,blocked,note,ts) VALUES(?,?,1,?,?)",
                   (target,"blocked",f"Blocked by DFIR: {session.get('user')}",
                    datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S")))
        db.connection.commit()
        write_log("security","CRITICAL",f"DFIR: IP {target} blocked by {session.get('user')}",ip=target)
        update_breach(pct_delta=-5)
        result = f"IP {target} blocked"

    elif action == "disable_account":
        db.execute("UPDATE users SET active=0 WHERE username=?",(target,))
        db.connection.commit()
        write_log("auth","CRITICAL",f"DFIR: Account {target} disabled by {session.get('user')}")
        update_breach(pct_delta=-8)
        result = f"Account {target} disabled"

    elif action == "revoke_sessions":
        db.execute("UPDATE users SET sessions_revoked=1 WHERE username=?",(target,))
        db.connection.commit()
        write_log("auth","HIGH",f"DFIR: All sessions revoked for {target}")
        update_breach(pct_delta=-5)
        result = f"Sessions revoked for {target}"

    elif action == "remove_malware":
        write_log("endpoint","HIGH","DFIR: Webshell removed from /uploads/shell.php")
        update_breach(pct_delta=-12)
        result = "Webshell removed — system patched"

    elif action == "restore_services":
        write_log("syslog","INFO","DFIR: Services restored to known-good state")
        update_breach(pct_delta=-10)
        result = "Services restored"

    db.execute("INSERT INTO dfir_actions(action,target,performed_by,result) VALUES(?,?,?,?)",
               (action, target, session.get("user"), result))
    db.connection.commit()
    return jsonify({"status":"ok","result":result,"breach":get_breach()})

@app.route("/api/dfir/timeline")
@role_required("dfir","admin")
def api_dfir_timeline():
    db = get_db()
    logs = db.execute(
        "SELECT ts,source,level,message,ip,username,stage_triggered,incident_id FROM logs"
        " WHERE stage_triggered > 0 ORDER BY ts ASC LIMIT 300"
    ).fetchall()
    return jsonify([dict(r) for r in logs])

# ─── GRC ROUTES ───────────────────────────────────────────────────────────────
@app.route("/grc/dashboard")
@role_required("grc","admin")
def grc_dashboard():
    db = get_db()
    submissions = db.execute("SELECT * FROM grc_submissions ORDER BY ts DESC").fetchall()
    return render_template("grc_dashboard.html", submissions=submissions)

@app.route("/grc/mentor")
@role_required("grc","admin")
def grc_mentor():
    return render_template("grc_mentor.html")

ISO_CONTROLS = [
    {"id":"A.5.1","name":"Policies for Information Security","category":"Organizational","weight":5},
    {"id":"A.6.1","name":"Internal Organization","category":"Organizational","weight":4},
    {"id":"A.8.1","name":"Responsibility for Assets","category":"Asset Management","weight":6},
    {"id":"A.9.1","name":"Business Requirements of Access Control","category":"Access Control","weight":8},
    {"id":"A.9.2","name":"User Access Management","category":"Access Control","weight":8},
    {"id":"A.9.4","name":"System and Application Access Control","category":"Access Control","weight":9},
    {"id":"A.10.1","name":"Cryptographic Controls","category":"Cryptography","weight":7},
    {"id":"A.12.1","name":"Operational Procedures and Responsibilities","category":"Operations","weight":6},
    {"id":"A.12.6","name":"Technical Vulnerability Management","category":"Operations","weight":10},
    {"id":"A.13.1","name":"Network Security Management","category":"Network","weight":8},
    {"id":"A.14.2","name":"Security in Development and Support","category":"Development","weight":7},
    {"id":"A.16.1","name":"Management of Information Security Incidents","category":"Incident Response","weight":9},
    {"id":"A.17.1","name":"Business Continuity","category":"Business Continuity","weight":7},
    {"id":"A.18.1","name":"Compliance with Legal Requirements","category":"Compliance","weight":8},
]

@app.route("/api/grc/controls")
@role_required("grc","admin")
def api_grc_controls():
    return jsonify(ISO_CONTROLS)

@app.route("/api/grc/gap_analysis")
@role_required("grc","admin")
def api_grc_gap_analysis():
    breach = get_breach()
    stage = breach.get("current_stage",0)
    # Map breach stage to failed controls
    gaps = []
    if stage >= 1:
        gaps.append({"control":"A.9.4","issue":"No account lockout after brute force","severity":"CRITICAL","nist":"AC-7"})
    if stage >= 3:
        gaps.append({"control":"A.14.2","issue":"SQL injection vulnerability — parameterized queries not used","severity":"CRITICAL","nist":"SA-11"})
    if stage >= 5:
        gaps.append({"control":"A.9.1","issue":"IDOR — missing object-level authorization","severity":"HIGH","nist":"AC-3"})
    if stage >= 6:
        gaps.append({"control":"A.13.1","issue":"SSRF — no egress filtering on internal network","severity":"CRITICAL","nist":"SC-7"})
    if stage >= 7:
        gaps.append({"control":"A.9.2","issue":"Privilege escalation via role manipulation","severity":"CRITICAL","nist":"AC-6"})
    if stage >= 9:
        gaps.append({"control":"A.12.6","issue":"File upload — no content-type validation or sandboxing","severity":"CRITICAL","nist":"SI-3"})
    if stage >= 12:
        gaps.append({"control":"A.13.1","issue":"Data exfiltration — no DLP controls on egress","severity":"CRITICAL","nist":"SC-7"})
    return jsonify({"gaps":gaps, "total_controls":len(ISO_CONTROLS), "failing":len(gaps)})

@app.route("/api/grc/risk_register")
@role_required("grc","admin")
def api_grc_risk_register():
    breach = get_breach()
    stage = breach.get("current_stage",0)
    risks = [
        {"id":"RR-001","risk":"Unauthorized access via credential compromise","likelihood":4 if stage>=1 else 2,"impact":4,"control":"A.9.4","status":"OPEN" if stage>=1 else "MITIGATED"},
        {"id":"RR-002","risk":"SQL injection leading to data breach","likelihood":5 if stage>=3 else 1,"impact":5,"control":"A.14.2","status":"OPEN" if stage>=3 else "MITIGATED"},
        {"id":"RR-003","risk":"Insider threat — unauthorized data access","likelihood":3,"impact":4,"control":"A.9.1","status":"MONITORING"},
        {"id":"RR-004","risk":"Web application compromise via file upload","likelihood":4 if stage>=9 else 1,"impact":5,"control":"A.12.6","status":"OPEN" if stage>=9 else "MITIGATED"},
        {"id":"RR-005","risk":"Data exfiltration via network channel","likelihood":5 if stage>=12 else 1,"impact":5,"control":"A.13.1","status":"CRITICAL" if stage>=12 else "MITIGATED"},
        {"id":"RR-006","risk":"Privilege escalation — lateral movement","likelihood":4 if stage>=7 else 1,"impact":5,"control":"A.9.2","status":"OPEN" if stage>=7 else "MITIGATED"},
    ]
    return jsonify(risks)

@app.route("/api/grc/submit", methods=["POST"])
@role_required("grc","admin")
def api_grc_submit():
    data = request.json or {}
    db = get_db()
    score = 0
    control = data.get("control","")
    status = data.get("status","")
    evidence = data.get("evidence","")
    ctrl = next((c for c in ISO_CONTROLS if c["id"]==control), None)
    if ctrl:
        if status == "implemented": score = ctrl["weight"]
        elif status == "partial": score = ctrl["weight"] * 0.5
        elif status == "planned": score = ctrl["weight"] * 0.2
    db.execute("INSERT INTO grc_submissions(team,control,status,evidence,score) VALUES(?,?,?,?,?)",
               (session.get("user"), control, status, evidence, score))
    db.connection.commit()
    return jsonify({"status":"ok","score":score,"control":control})

# ─── WIN CONDITIONS & RESET ────────────────────────────────────────────────────
@app.route("/api/win_conditions")
def api_win_conditions():
    breach = get_breach()
    db = get_db()
    dfir_count = db.execute("SELECT COUNT(*) FROM dfir_actions").fetchone()[0]
    sigma_count = db.execute("SELECT COUNT(*) FROM sigma_triggers").fetchone()[0]
    grc_score = db.execute("SELECT SUM(score) FROM grc_submissions").fetchone()[0] or 0
    stage = breach.get("current_stage",0)

    # Win conditions
    red_won = stage >= 12 and breach.get("breach_pct",0) >= 90
    blue_won = (breach.get("dfir_unlocked") and dfir_count >= 3
                and breach.get("breach_pct",0) <= 40)
    return jsonify({
        "breach_pct": breach.get("breach_pct",0),
        "current_stage": stage,
        "dfir_unlocked": breach.get("dfir_unlocked",0),
        "soc_escalated": breach.get("soc_escalated",0),
        "red_ip": breach.get("red_ip",""),
        "dfir_actions": dfir_count,
        "sigma_detections": sigma_count,
        "grc_score": round(grc_score,1),
        "red_team_win": red_won,
        "blue_team_win": blue_won,
        "attack_stages_completed": stage,
        "total_stages": 12,
    })

@app.route("/mentor/reset", methods=["POST"])
def mentor_reset():
    key = request.form.get("key","") or (request.json or {}).get("key","")
    if key != "NULLGRIDS_MENTOR_RESET":
        return jsonify({"error":"Invalid reset key"}), 403
    conn = sqlite3.connect(DB_PATH, timeout=5)
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("DELETE FROM logs")
    conn.execute("DELETE FROM attack_chain")
    conn.execute("DELETE FROM sigma_triggers")
    conn.execute("DELETE FROM dfir_actions")
    conn.execute("DELETE FROM grc_submissions")
    conn.execute("DELETE FROM packets")
    conn.execute("DELETE FROM ip_tags")
    conn.execute("UPDATE breach_state SET breach_pct=0,current_stage=0,dfir_unlocked=0,soc_escalated=0,red_ip='',chain_id=? WHERE id=1",
                 (str(uuid.uuid4())[:8],))
    conn.execute("UPDATE users SET active=1,sessions_revoked=0")
    conn.commit()
    conn.close()
    return jsonify({"status":"reset","message":"All competition data cleared. System ready."})

@app.route("/error")
def error_page():
    return render_template("error.html", msg="Page not found"), 404

if __name__ == "__main__":
    if not os.path.exists(DB_PATH):
        print("[*] Initializing database...")
        init_db()
    else:
        # Re-seed if needed
        conn = sqlite3.connect(DB_PATH)
        cnt = conn.execute("SELECT COUNT(*) FROM users").fetchone()[0]
        conn.close()
        if cnt == 0:
            init_db()
        else:
            print("[✓] Database exists")

    # Start background threads
    bg = threading.Thread(target=background_log_engine, daemon=True)
    bg.start()
    sg = threading.Thread(target=sigma_detection_engine, daemon=True)
    sg.start()
    print("""
╔═══════════════════════════════════════════════════════════╗
║     NullGrids Red vs Blue — Enterprise Cyber Range        ║
╠═══════════════════════════════════════════════════════════╣
║  Company Site:  http://localhost:5000/                    ║
║  Red Team:      http://localhost:5000/login               ║
║  SOC Monitor:   http://localhost:5000/soc/monitor         ║
║  DFIR Portal:   http://localhost:5000/dfir                ║
║  GRC System:    http://localhost:5000/grc/dashboard       ║
╠═══════════════════════════════════════════════════════════╣
║  SOC Login:     soc_analyst / SOCpass2024!                ║
║  DFIR Login:    dfir_lead   / DFIRpass2024!               ║
║  GRC Login:     grc_manager / GRCpass2024!                ║
║  Red Entry:     /login  (brute force jdoe/admin)          ║
║  Mentor Reset:  POST /mentor/reset  key=NULLGRIDS_MENTOR_RESET
╚═══════════════════════════════════════════════════════════╝
    """)
    app.run(debug=False, host="0.0.0.0", port=5000, threaded=True)
