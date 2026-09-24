"""Business-risk vulnerability dashboard (HTH-CS-03).
Run:  uvicorn main:app --reload   ->  http://127.0.0.1:8000
"""
import json, ipaddress, shutil, socket, sqlite3, subprocess
from datetime import datetime, timezone
import xml.etree.ElementTree as ET
from pathlib import Path

from fastapi import FastAPI, HTTPException
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

BASE = Path(__file__).parent
ASSETS_FILE = BASE / "assets.json"
FINDINGS_FILE = BASE / "findings.json"
SCAN_HISTORY_FILE = BASE / "scan_history.json"
DATABASE_FILE = BASE / "security.db"
EXPOSURE = {"internet": 1.0, "internal": 0.6, "isolated": 0.25}
VERSION_BASELINES = {
    "apache": ("2.4.0", "Apache 2.4+ baseline"),
    "openssh": ("7.0", "OpenSSH 7+ baseline"),
    "vsftpd": ("3.0.0", "vsftpd 3+ baseline"),
    "samba": ("4.0.0", "Samba 4+ baseline"),
    "mysql": ("5.7.0", "MySQL 5.7+ baseline"),
    "nginx": ("1.18.0", "nginx 1.18+ baseline"),
}
PORT_FINDING_RULES = {
    21: ("FTP service exposed", 6.5, 0.35, "Disable FTP or restrict it to the lab network"),
    23: ("Telnet service exposed", 7.5, 0.30, "Disable Telnet and use SSH"),
    445: ("SMB service exposed", 7.5, 0.35, "Restrict SMB to trusted internal hosts"),
    3306: ("MySQL service exposed", 6.5, 0.40, "Bind MySQL to localhost or a private application network"),
    3389: ("RDP service exposed", 7.5, 0.35, "Restrict RDP behind a VPN or approved administrator network"),
}
SERVICE_FIXES = {
    "apache": "Upgrade Apache and review supported PHP versions",
    "openssh": "Upgrade OpenSSH to a supported release",
    "vsftpd": "Upgrade vsftpd or disable FTP",
    "samba": "Upgrade Samba to a supported release",
    "mysql": "Upgrade MySQL and apply vendor security updates",
    "nginx": "Upgrade nginx to a supported release",
}


def resolve_nmap_executable():
    """Find nmap in PATH or in the common Windows install locations."""
    existing = shutil.which("nmap")
    if existing:
        return existing

    for candidate in (
        Path(r"C:\Program Files (x86)\Nmap\nmap.exe"),
        Path(r"C:\Program Files\Nmap\nmap.exe"),
    ):
        if candidate.exists():
            return str(candidate)

    return None


app = FastAPI(title="Business-Risk Vulnerability Dashboard")


def load(path):
    return json.loads(path.read_text())


def save(path, value):
    path.write_text(json.dumps(value, indent=2))


def database():
    connection = sqlite3.connect(DATABASE_FILE)
    connection.row_factory = sqlite3.Row
    return connection


def init_database():
    with database() as connection:
        connection.executescript("""
            CREATE TABLE IF NOT EXISTS assets (
                id TEXT PRIMARY KEY, name TEXT NOT NULL, ip TEXT NOT NULL,
                criticality INTEGER NOT NULL, exposure TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS findings (
                id INTEGER PRIMARY KEY AUTOINCREMENT, asset TEXT NOT NULL,
                title TEXT NOT NULL, cve TEXT, cvss REAL NOT NULL,
                epss REAL NOT NULL, kev INTEGER NOT NULL, fix_id TEXT NOT NULL,
                fix TEXT NOT NULL, effort INTEGER NOT NULL
            );
            CREATE TABLE IF NOT EXISTS scans (
                id INTEGER PRIMARY KEY AUTOINCREMENT, target TEXT NOT NULL,
                scanned_at TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS scan_ports (
                id INTEGER PRIMARY KEY AUTOINCREMENT, scan_id INTEGER NOT NULL,
                port INTEGER NOT NULL, proto TEXT NOT NULL, service TEXT,
                version TEXT, version_status TEXT NOT NULL, version_note TEXT,
                FOREIGN KEY(scan_id) REFERENCES scans(id)
            );
            CREATE TABLE IF NOT EXISTS scan_findings (
                id INTEGER PRIMARY KEY AUTOINCREMENT, scan_id INTEGER NOT NULL,
                asset TEXT NOT NULL, title TEXT NOT NULL, cve TEXT,
                cvss REAL NOT NULL, epss REAL NOT NULL, kev INTEGER NOT NULL,
                fix_id TEXT NOT NULL, fix TEXT NOT NULL, effort INTEGER NOT NULL,
                FOREIGN KEY(scan_id) REFERENCES scans(id)
            );
            CREATE TABLE IF NOT EXISTS remediation_state (
                finding_key TEXT PRIMARY KEY, status TEXT NOT NULL,
                updated_at TEXT NOT NULL
            );
        """)
        if connection.execute("SELECT COUNT(*) FROM assets").fetchone()[0] == 0:
            connection.executemany(
                "INSERT INTO assets VALUES (?, ?, ?, ?, ?)",
                [(a["id"], a["name"], a["ip"], a["criticality"], a["exposure"])
                 for a in load(ASSETS_FILE)])
        if connection.execute("SELECT COUNT(*) FROM findings").fetchone()[0] == 0:
            connection.executemany(
                "INSERT INTO findings (asset, title, cve, cvss, epss, kev, fix_id, fix, effort) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
                [(f["asset"], f["title"], f.get("cve", ""), f["cvss"], f["epss"],
                  int(f["kev"]), f["fix_id"], f["fix"], f["effort"])
                 for f in load(FINDINGS_FILE)])
        if connection.execute("SELECT COUNT(*) FROM scans").fetchone()[0] == 0 and SCAN_HISTORY_FILE.exists():
            for scan_result in load(SCAN_HISTORY_FILE):
                cursor = connection.execute(
                    "INSERT INTO scans (target, scanned_at) VALUES (?, ?)",
                    (scan_result["target"], scan_result["scanned_at"]))
                for port in scan_result.get("open_ports", []):
                    connection.execute(
                        "INSERT INTO scan_ports (scan_id, port, proto, service, version, version_status, version_note) VALUES (?, ?, ?, ?, ?, ?, ?)",
                        (cursor.lastrowid, port["port"], port["proto"], port.get("service", ""),
                         port.get("version", ""), port.get("version_status", "unknown"), port.get("version_note", "")))


def read_assets():
    with database() as connection:
        return [dict(row) for row in connection.execute("SELECT id, name, ip, criticality, exposure FROM assets ORDER BY id")]


def read_findings():
    with database() as connection:
        findings = [dict(row) for row in connection.execute(
            "SELECT asset, title, cve, cvss, epss, kev, fix_id, fix, effort FROM findings ORDER BY id")]
        findings.extend(dict(row) for row in connection.execute("""
            SELECT sf.asset, sf.title, sf.cve, sf.cvss, sf.epss, sf.kev,
                   sf.fix_id, sf.fix, sf.effort
            FROM scan_findings sf
            JOIN scans s ON s.id = sf.scan_id
            WHERE s.id = (
                SELECT latest.id FROM scans latest
                WHERE latest.target = s.target
                ORDER BY latest.scanned_at DESC, latest.id DESC LIMIT 1
            )
            ORDER BY sf.id
        """))
        return findings


init_database()


def version_tuple(value):
    parts = []
    for part in value.split("."):
        digits = "".join(ch for ch in part if ch.isdigit())
        if not digits:
            break
        parts.append(int(digits))
    return tuple(parts) if parts else None


def assess_version(service, version):
    service_name = service.lower()
    baseline = next((value for name, value in VERSION_BASELINES.items() if name in service_name), None)
    detected = version_tuple(version)
    if not baseline or not detected:
        return {"version_status": "unknown", "version_note": "No baseline available"}

    minimum, label = baseline
    is_outdated = detected < version_tuple(minimum)
    return {
        "version_status": "outdated" if is_outdated else "baseline-ok",
        "version_note": f"{label}; detected {version}",
    }


def score(f, asset):
    """risk = exploitability x asset criticality x exposure (0-100)."""
    expl = 0.45 * f["epss"] + 0.35 * (1 if f["kev"] else 0) + 0.20 * f["cvss"] / 10
    crit = asset["criticality"] / 5
    expo = EXPOSURE[asset["exposure"]]
    return {
        "exploitability": round(expl, 2),
        "criticality_factor": crit,
        "exposure_factor": expo,
        "risk": round(expl * crit * expo * 100, 1),
    }


def finding_key(f):
    return "|".join(str(f.get(field, "")) for field in ("asset", "title", "cve"))


def remediation_states():
    with database() as connection:
        return {row["finding_key"]: row["status"] for row in connection.execute(
            "SELECT finding_key, status FROM remediation_state")}


def risk_level(value):
    return "critical" if value >= 30 else "high" if value >= 15 else "medium" if value >= 6 else "low"


def enrich_finding(finding, asset, state):
    result = {**finding, **score(finding, asset), "asset_name": asset["name"]}
    result["finding_key"] = finding_key(result)
    result["status"] = state.get(result["finding_key"], "open")
    result["technical_severity"] = round(float(result["cvss"]), 1)
    result["technical_severity_label"] = "critical" if result["cvss"] >= 9 else "high" if result["cvss"] >= 7 else "medium" if result["cvss"] >= 4 else "low"
    result["asset_criticality_label"] = "critical" if asset["criticality"] >= 5 else "high" if asset["criticality"] >= 4 else "medium" if asset["criticality"] >= 3 else "low"
    result["exposure_label"] = "internet-facing" if asset["exposure"] == "internet" else asset["exposure"]
    result["business_impact"] = result["asset_criticality_label"]
    result["business_impact_factor"] = result["criticality_factor"]
    result["priority"] = "critical" if result["risk"] >= 30 else "high" if result["risk"] >= 15 else "medium" if result["risk"] >= 6 else "routine"
    result["effective_risk"] = result["risk"] if result["status"] != "remediated" else 0
    result["projected_risk"] = 0
    result["risk_removed"] = result["effective_risk"]
    result["risk_reduction_pct"] = round(result["risk_removed"] / result["risk"] * 100, 1) if result["risk"] else 0
    return result


def build_report(capacity):
    assets = read_assets()
    by_id = {a["id"]: a for a in assets}
    states = remediation_states()

    findings = []
    for f in read_findings():
        f["kev"] = bool(f["kev"])
        a = by_id.get(f["asset"])
        if a:
            findings.append(enrich_finding(f, a, states))

    findings.sort(key=lambda x: -x["risk"])
    for i, f in enumerate(findings, 1):
        f["rank"] = i
    for i, f in enumerate(sorted(findings, key=lambda x: -x["cvss"]), 1):
        f["cvss_rank"] = i

    # One fix can remove many findings -> plan fixes, not findings.
    fixes = {}
    for f in findings:
        if f["effective_risk"] <= 0:
            continue
        fx = fixes.setdefault(f["fix_id"], {
            "fix_id": f["fix_id"], "title": f["fix"], "asset_name": f["asset_name"],
            "effort": f["effort"], "risk_removed": 0, "findings": []})
        fx["risk_removed"] = round(fx["risk_removed"] + f["effective_risk"], 1)
        fx["findings"].append(f["title"])
    plan = sorted(fixes.values(), key=lambda x: (-x["risk_removed"], x["effort"]))

    total = round(sum(f["effective_risk"] for f in findings), 1)
    weeks, trend, left = [], [total], total
    for i in range(0, len(plan), capacity):
        batch = plan[i:i + capacity]
        left = max(round(left - sum(x["risk_removed"] for x in batch), 1), 0)
        weeks.append({"week": i // capacity + 1, "fixes": batch, "residual_risk": left})
        trend.append(left)

    top = findings[0] if findings else None
    concentration = []
    for asset in assets:
        asset_risk = round(sum(f["effective_risk"] for f in findings if f["asset"] == asset["id"]), 1)
        if asset_risk:
            concentration.append({"asset_id": asset["id"], "asset_name": asset["name"], "risk": asset_risk})
    concentration.sort(key=lambda item: -item["risk"])
    concentration_total = sum(item["risk"] for item in concentration) or 1
    for item in concentration:
        item["percentage"] = round(item["risk"] / concentration_total * 100, 1)

    posture = {
        "business_risk": total,
        "critical_findings": sum(1 for f in findings if f["effective_risk"] >= 30),
        "high_findings": sum(1 for f in findings if 15 <= f["effective_risk"] < 30),
        "affected_assets": sum(1 for item in concentration if item["risk"] > 0),
        "resolved_findings": sum(1 for f in findings if f["status"] == "remediated"),
        "risk_reduced": round(sum(f["risk"] - f["effective_risk"] for f in findings), 1),
        "remediation_progress": round(sum(1 for f in findings if f["status"] == "remediated") / len(findings) * 100, 1) if findings else 0,
    }

    why_top = None
    if top:
        why_top = {
            "finding_key": top["finding_key"],
            "title": top["title"],
            "asset_name": top["asset_name"],
            "business_risk": top["effective_risk"],
            "risk_removed": top["risk_removed"],
            "factors": {
                "technical_severity": top["technical_severity_label"],
                "asset_criticality": top["asset_criticality_label"],
                "exposure": top["exposure_label"],
                "exploitability": risk_level(top["exploitability"] * 100),
                "business_impact": top["business_impact"],
            },
            "explanation": f"This finding ranks first because it affects a {top['asset_criticality_label']} asset, is {top['exposure_label']}, and has {risk_level(top['exploitability'] * 100)} exploitability.",
        }

    attack_paths = [{
        "finding_key": f["finding_key"],
        "asset_name": f["asset_name"],
        "exposure": f["exposure_label"],
        "finding": f["title"],
        "impact": f["business_impact"],
        "inferred": True,
    } for f in findings[:5]]

    return {"assets": assets, "findings": findings, "total_risk": total,
            "capacity": capacity, "roadmap": weeks, "trend": trend,
            "ai_insights": build_ai_insights(findings, assets),
            "risk_concentration": concentration,
            "posture": posture,
            "why_top": why_top,
            "attack_paths": attack_paths}


def build_ai_insights(findings, assets):
    """Generate transparent, local risk insights from the available evidence."""
    asset_by_id = {asset["id"]: asset for asset in assets}
    priorities = []
    for finding in findings:
        asset = asset_by_id[finding["asset"]]
        signals = []
        if finding["kev"]:
            signals.append("known exploited")
        if finding["epss"] >= 0.7:
            signals.append("high exploitation probability")
        if asset["criticality"] >= 4:
            signals.append("business-critical asset")
        if asset["exposure"] == "internet":
            signals.append("internet exposed")
        reason = ", ".join(signals) if signals else "moderate combined risk signals"
        priorities.append({
            "title": finding["title"],
            "asset_name": finding["asset_name"],
            "risk": finding["risk"],
            "priority": "urgent" if finding["risk"] >= 15 or finding["kev"] else "high" if finding["risk"] >= 6 else "routine",
            "reason": reason,
            "recommendation": finding["fix"],
            "confidence": "high" if len(signals) >= 2 else "medium",
        })
    priorities.sort(key=lambda item: -item["risk"])
    return {
        "method": "Explainable local scoring using CVSS, EPSS, KEV, criticality, and exposure",
        "priorities": priorities[:5],
        "summary": f"Prioritize {priorities[0]['title']} on {priorities[0]['asset_name']} first." if priorities else "No findings require attention.",
    }


@app.get("/api/report")
def report(capacity: int = 5):
    return build_report(max(1, min(capacity, 50)))


class SimulationRequest(BaseModel):
    finding_keys: list[str] = []


@app.post("/api/simulate")
def simulate_remediation(body: SimulationRequest):
    data = build_report(50)
    selected = set(body.finding_keys)
    current = round(sum(f["effective_risk"] for f in data["findings"]), 1)
    selected_findings = [f for f in data["findings"] if f["finding_key"] in selected and f["status"] != "remediated"]
    removed = round(sum(f["risk"] for f in selected_findings), 1)
    projected = round(max(current - removed, 0), 1)
    return {
        "current_risk": current,
        "projected_risk": projected,
        "risk_removed": removed,
        "risk_reduction_pct": round(removed / current * 100, 1) if current else 0,
        "selected": [{"finding_key": f["finding_key"], "title": f["title"], "asset_name": f["asset_name"], "risk_removed": f["risk"]} for f in selected_findings],
    }


@app.post("/api/remediations/apply")
def apply_remediation(body: SimulationRequest):
    timestamp = datetime.now(timezone.utc).isoformat()
    with database() as connection:
        for key in set(body.finding_keys):
            connection.execute(
                "INSERT INTO remediation_state (finding_key, status, updated_at) VALUES (?, 'remediated', ?) "
                "ON CONFLICT(finding_key) DO UPDATE SET status = 'remediated', updated_at = excluded.updated_at",
                (key, timestamp))
    return build_report(5)


class WhatIfRequest(BaseModel):
    asset_id: str
    criticality: int
    exposure: str


@app.post("/api/risk-what-if")
def risk_what_if(body: WhatIfRequest):
    if not 1 <= body.criticality <= 5 or body.exposure not in EXPOSURE:
        raise HTTPException(400, "criticality must be 1-5; exposure internet/internal/isolated")
    data = build_report(50)
    asset = next((item for item in data["assets"] if item["id"] == body.asset_id), None)
    if not asset:
        raise HTTPException(404, "Unknown asset")
    hypothetical = {**asset, "criticality": body.criticality, "exposure": body.exposure}
    affected = [f for f in data["findings"] if f["asset"] == body.asset_id]
    current = round(sum(f["effective_risk"] for f in affected), 1)
    projected = round(sum(score(f, hypothetical)["risk"] for f in affected if f["status"] != "remediated"), 1)
    return {
        "asset_id": body.asset_id,
        "current": {"criticality": asset["criticality"], "exposure": asset["exposure"], "risk": current},
        "what_if": {"criticality": body.criticality, "exposure": body.exposure, "risk": projected},
        "delta": round(projected - current, 1),
        "factors_changed": [field for field in ("criticality", "exposure") if asset[field] != hypothetical[field]],
    }


def scan_snapshot(scan_id):
    with database() as connection:
        scan = connection.execute("SELECT id, target, scanned_at FROM scans WHERE id = ?", (scan_id,)).fetchone()
        if not scan:
            raise HTTPException(404, "Unknown scan")
        ports = [dict(row) for row in connection.execute(
            "SELECT port, proto, service, version, version_status, version_note FROM scan_ports WHERE scan_id = ? ORDER BY port", (scan_id,))]
        findings = [dict(row) for row in connection.execute(
            "SELECT asset, title, cve, cvss, epss, kev, fix_id, fix, effort FROM scan_findings WHERE scan_id = ? ORDER BY id", (scan_id,))]
    return {**dict(scan), "open_ports": ports, "findings": findings}


@app.get("/api/scan-comparison")
def scan_comparison(before_id: int, after_id: int):
    before = scan_snapshot(before_id)
    after = scan_snapshot(after_id)
    before_keys = {finding_key(item) for item in before["findings"]}
    after_keys = {finding_key(item) for item in after["findings"]}
    resolved = sorted(before_keys - after_keys)
    new = sorted(after_keys - before_keys)
    remaining = sorted(before_keys & after_keys)
    before_risk = round(sum(score(f, next((a for a in read_assets() if a["id"] == f["asset"]), {"criticality": 1, "exposure": "internal"}))['risk'] for f in before["findings"]), 1)
    after_risk = round(sum(score(f, next((a for a in read_assets() if a["id"] == f["asset"]), {"criticality": 1, "exposure": "internal"}))['risk'] for f in after["findings"]), 1)
    return {
        "before": {"id": before["id"], "scanned_at": before["scanned_at"], "findings": len(before["findings"]), "risk": before_risk},
        "after": {"id": after["id"], "scanned_at": after["scanned_at"], "findings": len(after["findings"]), "risk": after_risk},
        "resolved": resolved, "new": new, "remaining": remaining,
        "risk_reduction_pct": round((before_risk - after_risk) / before_risk * 100, 1) if before_risk else 0,
    }


class AssetUpdate(BaseModel):
    criticality: int
    exposure: str


@app.put("/api/assets/{asset_id}")
def update_asset(asset_id: str, body: AssetUpdate):
    if not 1 <= body.criticality <= 5 or body.exposure not in EXPOSURE:
        raise HTTPException(400, "criticality must be 1-5; exposure internet/internal/isolated")
    with database() as connection:
        connection.execute(
            "UPDATE assets SET criticality = ?, exposure = ? WHERE id = ?",
            (body.criticality, body.exposure, asset_id))
        row = connection.execute(
            "SELECT id, name, ip, criticality, exposure FROM assets WHERE id = ?",
            (asset_id,)).fetchone()
    if row:
        return dict(row)
    raise HTTPException(404, "Unknown asset")


class ScanRequest(BaseModel):
    target: str


def resolve_target_ip(target: str):
    """Accept either an IP address or a host/domain name, then resolve to a safe private/loopback IP."""
    value = target.strip()
    if not value:
        raise HTTPException(400, "Enter the IP address or hostname of your lab target")

    try:
        return ipaddress.ip_address(value)
    except ValueError:
        pass

    try:
        infos = socket.getaddrinfo(value, None, type=socket.SOCK_STREAM)
    except socket.gaierror as exc:
        raise HTTPException(400, f"Could not resolve host '{value}'") from exc

    for family, _, _, _, sockaddr in infos:
        addr = sockaddr[0]
        try:
            resolved = ipaddress.ip_address(addr)
            if resolved.is_private or resolved.is_loopback:
                return resolved
        except ValueError:
            continue

    # If a domain resolves to a public IP, reject it before scanning.
    for family, _, _, _, sockaddr in infos:
        addr = sockaddr[0]
        try:
            resolved = ipaddress.ip_address(addr)
            if not (resolved.is_private or resolved.is_loopback):
                raise HTTPException(403, "Blocked: only private/lab hosts may be scanned")
        except ValueError:
            continue

    raise HTTPException(400, f"Could not resolve a private/loopback address for '{value}'")


def ensure_scan_asset(target):
    """Attach a scan to a catalog asset, or create a low-trust lab asset."""
    target_value = str(target)
    with database() as connection:
        rows = [dict(row) for row in connection.execute("SELECT id, ip FROM assets")]
        for asset in rows:
            if asset["ip"] == target_value or asset["ip"].split(":")[0] == target_value:
                return asset["id"]
        asset_id = "scan-" + "".join(ch if ch.isalnum() else "-" for ch in target_value).strip("-")
        connection.execute(
            "INSERT OR IGNORE INTO assets (id, name, ip, criticality, exposure) VALUES (?, ?, ?, ?, ?)",
            (asset_id, f"Scanned lab target ({target_value})", target_value, 1, "internal"))
        return asset_id


def build_scan_findings(services, asset_id):
    """Convert only known Nmap observations into conservative findings."""
    findings = []
    for service in services:
        service_name = service["service"].lower()
        if service["version_status"] == "outdated":
            product = service_name or "service"
            fix = next((fix for name, fix in SERVICE_FIXES.items() if name in service_name),
                       f"Upgrade or remove the outdated {product} service")
            findings.append({
                "asset": asset_id,
                "title": f"Outdated {product} {service['version']}",
                "cve": "", "cvss": 7.5, "epss": 0.60, "kev": False,
                "fix_id": f"nmap-outdated-{service['port']}", "fix": fix, "effort": 2,
            })

        rule = PORT_FINDING_RULES.get(service["port"])
        if rule:
            title, cvss, epss, fix = rule
            findings.append({
                "asset": asset_id,
                "title": title,
                "cve": "", "cvss": cvss, "epss": epss, "kev": False,
                "fix_id": f"nmap-port-{service['port']}", "fix": fix, "effort": 1,
            })
    return findings


def perform_scan(target):
    """Run and persist one authorized private/loopback Nmap scan."""
    target_ip = resolve_target_ip(target)
    if not (target_ip.is_private or target_ip.is_loopback):
        raise HTTPException(403, "Blocked: only private/lab targets may be scanned")

    nmap_bin = resolve_nmap_executable()
    if not nmap_bin:
        raise HTTPException(
            500,
            "nmap is not installed or not on PATH. Install it from nmap.org and make sure C:\\Program Files (x86)\\Nmap is available."
        )

    try:
        out = subprocess.run([nmap_bin, "-sV", "-T4", "-oX", "-", str(target_ip)],
                             capture_output=True, text=True, timeout=300).stdout
    except subprocess.TimeoutExpired:
        raise HTTPException(504, "Scan took longer than 5 minutes")

    services = []
    for port in ET.fromstring(out).iter("port"):
        state, svc = port.find("state"), port.find("service")
        if state is not None and state.get("state") == "open":
            service_name = svc.get("name", "") if svc is not None else ""
            service_version = " ".join(filter(None, [svc.get("product"), svc.get("version")])) if svc is not None else ""
            services.append({
                "port": int(port.get("portid")), "proto": port.get("protocol"),
                "service": service_name, "version": service_version,
                **assess_version(service_name, service_version)})

    result = {
        "target": str(target_ip),
        "scanned_at": datetime.now(timezone.utc).isoformat(),
        "open_ports": services,
    }
    asset_id = ensure_scan_asset(target_ip)
    live_findings = build_scan_findings(services, asset_id)
    with database() as connection:
        cursor = connection.execute(
            "INSERT INTO scans (target, scanned_at) VALUES (?, ?)",
            (result["target"], result["scanned_at"]))
        for service in services:
            connection.execute(
                "INSERT INTO scan_ports (scan_id, port, proto, service, version, version_status, version_note) VALUES (?, ?, ?, ?, ?, ?, ?)",
                (cursor.lastrowid, service["port"], service["proto"], service["service"],
                 service["version"], service["version_status"], service["version_note"]))
        for finding in live_findings:
            connection.execute(
                "INSERT INTO scan_findings (scan_id, asset, title, cve, cvss, epss, kev, fix_id, fix, effort) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (cursor.lastrowid, finding["asset"], finding["title"], finding["cve"],
                 finding["cvss"], finding["epss"], int(finding["kev"]), finding["fix_id"],
                 finding["fix"], finding["effort"]))
        connection.execute("""
            DELETE FROM scans
            WHERE id NOT IN (SELECT id FROM scans ORDER BY scanned_at DESC LIMIT 25)
        """)
    result["findings"] = live_findings
    return result


@app.post("/api/scan")
def scan(req: ScanRequest):
    """Synchronous service/version scan for existing API clients."""
    return perform_scan(req.target)


@app.get("/api/scans")
def scan_history():
    with database() as connection:
        scans = [dict(row) for row in connection.execute(
            "SELECT id, target, scanned_at FROM scans ORDER BY scanned_at DESC LIMIT 25")]
        for scan_result in scans:
            scan_result["open_ports"] = [dict(row) for row in connection.execute(
                "SELECT port, proto, service, version, version_status, version_note FROM scan_ports WHERE scan_id = ? ORDER BY port",
                (scan_result["id"],))]
    return scans


app.mount("/", StaticFiles(directory=BASE, html=True), name="static")
