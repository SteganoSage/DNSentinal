# DNSentinel Cybersecurity Gateway — Observability Dashboard

A cybersecurity dashboard for the **DNSentinel** secure recursive DNS resolver. Built with **React** (frontend), **FastAPI** (Python backend), and **SQLite** (local storage).

> ⚠️ **NOTICE: DEMO / SAMPLE DATA MODE**  
> All query logs, threat metrics, and alerts in this dashboard are clearly labeled demonstration and sample data. Modifying demo settings through this dashboard changes only the local demo SQLite database; the core resolver configuration (`config/dnsentinel.yaml`) is strictly isolated and never touched.

---

## 📁 Dashboard Structure

All dashboard files are isolated within the `dashboard/` directory:

```
dashboard/
├── backend/
│   ├── app/
│   │   ├── database.py       # SQLite connection and schema definitions
│   │   ├── models.py         # Pydantic data schemas
│   │   ├── sample_data.py    # Realistic seed queries, threats, and devices
│   │   ├── routers/          # FastAPI REST endpoints
│   │   │   ├── metrics.py    # /api/metrics & /api/activity
│   │   │   ├── queries.py    # /api/queries & /api/queries/simulate
│   │   │   ├── clients.py    # /api/clients
│   │   │   ├── alerts.py     # /api/alerts (with detailed forensic evidence)
│   │   │   └── settings.py   # /api/settings (demo sandbox only)
│   │   └── main.py           # FastAPI app, CORS, static SPA serving
│   ├── dnsentinel_demo.db    # SQLite database (auto-generated)
│   ├── requirements.txt      # Python dependencies
│   └── run_backend.py        # Direct launcher script
├── frontend/
│   ├── index.html            # Turnkey React 18 SPA (runs out-of-the-box)
│   ├── package.json          # Node/Vite package definition
│   └── src/                  # Modular React component source tree
│       ├── main.jsx
│       ├── App.jsx
│       ├── components/
│       └── pages/
├── run_dashboard.bat         # 1-Click launcher for Windows Command Prompt
├── start_dashboard.ps1       # 1-Click launcher for Windows PowerShell
└── README.md                 # This guide
```

---

## 🚀 How to Run the Dashboard on Windows

### Prerequisites
- **Python 3.10+** installed on Windows.

### Step 1: Install Python Dependencies (First Time Only)
Open PowerShell or Command Prompt in the repository root and run:
```powershell
py -m pip install fastapi uvicorn
```
*(or run `py -m pip install -r dashboard/backend/requirements.txt`)*

### Step 2: Start the Application

You can start the dashboard in **any of the following 3 ways**:

#### Option A: 1-Click Batch File (Easiest)
Double-click `dashboard\run_dashboard.bat` in Windows File Explorer.  
*(Or run `.\dashboard\run_dashboard.bat` from Command Prompt)*

#### Option B: PowerShell Script
```powershell
powershell -ExecutionPolicy Bypass -File .\dashboard\start_dashboard.ps1
```

#### Option C: Direct Python Command
```powershell
py dashboard/backend/run_backend.py
```

Then open your browser to **[http://127.0.0.1:8000](http://127.0.0.1:8000)**.

---

## 🖥️ Dashboard Pages & Features

### 1. Overview
- **Metric Cards**: Total DNS Queries, Blocked Queries, Cache Hit Ratio, and Average Latency.
- **Activity Timeline Chart**: Visualizes past query trends, allowed resolutions, and blocked attacks.
- **Defense Interceptions**: Percentage breakdown of blocked threat categories (DGA, Tunnels, CNAME Cloaking, Rebinding).
- **Recent Stream**: Real-time ticker showing the latest DNS query events.

### 2. DNS Queries
- **Real-Time Search & Filtering**: Filter by Status (`ALLOW` / `BLOCK`), Record Type (`A`, `AAAA`, `TXT`, `CNAME`), or Client IP.
- **Interactive Query Simulator**: Type any domain (e.g. `malware-botnet.biz` or `test-domain.org`) and hit **Test Query** to watch it pass through the policy engine and record into SQLite live!
- **Inspection Modal**: Click on any query row to view full packet details, latency, and interception reasons.

### 3. Clients
- **Device Inventory**: View connected network devices (SOC workstation, MacBook, IoT cameras, etc.).
- **Threat Levels**: Visual badges for `Low`, `Medium`, and `High` risk devices with individual block proportions.

### 4. Security Alerts
- **Threat Intelligence Feed**: Detailed detection cards for DGA Malware, DNS Exfiltration Tunnels, CNAME Cloaking, DNS Rebinding, and Cache Poisoning.
- **Forensic Explanations ("Why Flagged?")**: Clear breakdown of contributing features (Shannon entropy, consonant-to-vowel ratios, subdomain count, 0x20 case mismatches).
- **Mitigation Controls**: Mark alerts as `Mitigated` or `Dismissed` directly in the demo database.

### 5. Settings
- **Tunable Detection Knobs**: Adjust DGA classifier cutoff, tunnel entropy threshold, client rate limits, and negative cache TTL.
- **Defense Module Toggles**: Toggle CNAME inspection and 0x20 bit-case randomization.
- **Reset Demo Dataset**: Restore sample data to default with one click.
- **Safety Guarantee**: Settings modify the local SQLite demo state only; core resolver files remain untouched.
