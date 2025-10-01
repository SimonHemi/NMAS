Network Monitoring & Alert System (NMAS)
This project is a lightweight log ingestion and alerting system built for the Liberty University CSIS 484 Capstone. It ingests syslog-style messages, detects suspicious patterns (failed login bursts and port scans), and generates alerts that can be viewed in a simple Flask dashboard, exported to CSV/JSON/log files, or cleared via the admin panel.
Project Structure

Capstone/
  ingest/              # UDP syslog listener
  detect/              # Detection rules + alert writing
  alerts/              # Notification handlers (log, JSON, email, webhook)
  dashboard/           # Flask web UI (templates + routes)
  tests/               # Seed/test scripts
  events.db            # SQLite database (auto-created)
  config.json          # Configuration (listener, dashboard, email, webhook, logging)
dist/
  nmas.exe             # Single packaged executable (PyInstaller)

Requirements (if running from source)
- Python 3.11+
- Pip/venv for virtual environment
- Packages: flask, aiosmtpd (optional), sqlite3 (built-in)

Install dependencies:
pip install flask aiosmtpd
How to Run
Option A: Single Executable
After building with PyInstaller you will have:
dist/nmas.exe

Run all components (listener + detector + dashboard):
.\nmas.exe all

Run only one part:
.\nmas.exe listener     # syslog listener
.\nmas.exe detect       # detection pass
.\nmas.exe dashboard    # dashboard only
In the event the browser does not auto open, ctl+Lclick the link in the powershell that opens. 

The exe will auto-create events.db, alerts.log, and alerts.json in the same folder.
Option B: Run from Source
1. Start listener: python run_listener_local.py
2. Send test data: python Capstone/tests/seed_data.py
3. Run detection: python run_detection_local.py
4. Launch dashboard: python run_dashboard_local.py
Dashboard Features
Open http://127.0.0.1:5000

- Auth: default admin/admin (change in config.json).
- Filter by alert type and time range.
- Export alerts to CSV.
- Refresh button (🔄) and optional auto-refresh (15s).
- Test & Simulate:
   - Simulate failed-login bursts
   - Simulate port scans
   - Run detection immediately
Resetting
To fully reset NMAS:
1. Stop the program.
2. Delete: events.db, events.db-wal, events.db-shm, (optional) alerts.log, alerts.json
3. Restart the exe — fresh empty DB and logs will be created.
Evidence for Peer Review
- Listener console: [INSERT] messages for incoming logs
- Detection console: “Detection run @ … -> X new alerts”
- Dashboard: populated table, chart, and filters
- Export: CSV with alert data
- Prune: audit entry in alerts.log
Notes
- Default listener port: UDP 5514 (non-privileged).
- Change to 514 in config.json if running as admin/root.
- Devices must be configured to send syslog to the NMAS host.
- This project is a Capstone demo; not hardened for production.
Future Improvements
- Configurable detection thresholds in config.json
- Daily/weekly email summaries
- Docker container packaging
- Production-ready hardening (HTTPS, RBAC, stronger auth, logging rotation)


© 2025 Simon Peter Hemingway. All rights reserved.  
This project was created as part of a Capstone course at Liberty University.  
It is provided for educational purposes only and is not licensed for reuse,
reproduction, or distribution without permission.
