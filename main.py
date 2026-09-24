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
        return [dict(row) for row in connection.execute(
            "SELECT asset, title, cve, cvss, epss, kev, fix_id, fix, effort FROM findings ORDER BY id")]


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


def build_report(capacity):
    assets = read_assets()
    by_id = {a["id"]: a for a in assets}

    findings = []
    for f in read_findings():
        f["kev"] = bool(f["kev"])
        a = by_id[f["asset"]]
        findings.append({**f, **score(f, a), "asset_name": a["name"]})

    findings.sort(key=lambda x: -x["risk"])
    for i, f in enumerate(findings, 1):
        f["rank"] = i
    for i, f in enumerate(sorted(findings, key=lambda x: -x["cvss"]), 1):
        f["cvss_rank"] = i

    # One fix can remove many findings -> plan fixes, not findings.
    fixes = {}
    for f in findings:
        fx = fixes.setdefault(f["fix_id"], {
            "fix_id": f["fix_id"], "title": f["fix"], "asset_name": f["asset_name"],
            "effort": f["effort"], "risk_removed": 0, "findings": []})
        fx["risk_removed"] = round(fx["risk_removed"] + f["risk"], 1)
        fx["findings"].append(f["title"])
    plan = sorted(fixes.values(), key=lambda x: (-x["risk_removed"], x["effort"]))

    total = round(sum(f["risk"] for f in findings), 1)
    weeks, trend, left = [], [total], total
    for i in range(0, len(plan), capacity):
        batch = plan[i:i + capacity]
        left = max(round(left - sum(x["risk_removed"] for x in batch), 1), 0)
        weeks.append({"week": i // capacity + 1, "fixes": batch, "residual_risk": left})
        trend.append(left)

    return {"assets": assets, "findings": findings, "total_risk": total,
            "capacity": capacity, "roadmap": weeks, "trend": trend,
            "ai_insights": build_ai_insights(findings, assets)}


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


@app.post("/api/scan")
def scan(req: ScanRequest):
    """Service/version scan. Accept either a private IP or a lab hostname resolving to a private/loopback IP."""
    target_ip = resolve_target_ip(req.target)
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
    with database() as connection:
        cursor = connection.execute(
            "INSERT INTO scans (target, scanned_at) VALUES (?, ?)",
            (result["target"], result["scanned_at"]))
        for service in services:
            connection.execute(
                "INSERT INTO scan_ports (scan_id, port, proto, service, version, version_status, version_note) VALUES (?, ?, ?, ?, ?, ?, ?)",
                (cursor.lastrowid, service["port"], service["proto"], service["service"],
                 service["version"], service["version_status"], service["version_note"]))
        connection.execute("""
            DELETE FROM scans
            WHERE id NOT IN (SELECT id FROM scans ORDER BY scanned_at DESC LIMIT 25)
        """)
    return result


@app.get("/api/scans")
def scan_history():
    with database() as connection:
        scans = [dict(row) for row in connection.execute(
            "SELECT id, target, scanned_at FROM scans ORDER BY scanned_at DESC LIMIT 25")]
        for scan_result in scans:
            scan_result["open_ports"] = [dict(row) for row in connection.execute(
                "SELECT port, proto, service, version, version_status, version_note FROM scan_ports WHERE scan_id = ? ORDER BY port",
                (scan_result.pop("id"),))]
    return scans


app.mount("/", StaticFiles(directory=BASE, html=True), name="static")
