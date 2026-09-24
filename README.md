# Monday Fix List (HTH-CS-03)

Run it in VS Code (open the `vuln-dashboard` folder, then use the terminal):

```
python -m venv venv
venv\Scripts\activate          # Windows   (Mac/Linux: source venv/bin/activate)
pip install -r requirements.txt
uvicorn main:app --reload
```

Open http://127.0.0.1:8000

- `assets.json`  : your assets with criticality (1-5) and exposure (internet / internal / isolated)
- `findings.json`: findings with CVSS, EPSS, KEV, and the fix that clears them (illustrative values, replace with real scan + enrichment data)
- `security.db`  : SQLite database containing assets, findings, scan results, and scan ports. Existing JSON data is imported automatically on first run.
- Scan panel needs nmap (https://nmap.org). Only private/loopback IPs are accepted.
- Only scan machines you own or lab targets (Metasploitable, DVWA, Juice Shop).
