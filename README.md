# Behaviour-based Intrusion Prevention System (AI)

A showcase project for GitHub and LinkedIn. It reads network log CSV files from the `network/` folder, runs unsupervised behavior anomaly detection with **Isolation Forest**, and writes detailed findings with remediation steps.

## What this project does

- Reads CSV network logs from `network/` (one file per run)
- Learns normal behavior using `IsolationForest` (unsupervised AI)
- Flags suspicious records as anomalies
- Explains why each anomaly is risky
- Generates step-by-step remediation actions for analysts
- Exports reports to a new timestamped folder under `reports/` (example: `reports/2026-06-01_14-30-45/`)

## Requirements

- **Python 3.10+** (3.11 or 3.12 recommended)
- Windows, macOS, or Linux

## Folder structure

```text
behaviour-based-ips-ai/
├─ main.py
├─ requirements.txt
├─ first_time_setup.bat      # Windows: first-time venv + install + run
├─ run.bat                   # Windows: run analyzer (uses .venv if present)
├─ LINE_BY_LINE_GUIDE.md     # Optional walkthrough of the code
├─ network/
│  └─ sample_network_log.csv
├─ reports/                  # Generated report folders (created on run)
└─ ips_ai/
   ├─ __init__.py
   ├─ data_loader.py
   ├─ analyzer.py
   ├─ reporting.py
   ├─ html_report.py
   └─ progress.py
```

## Expected CSV columns

Your network log CSV should include these columns (extra columns are fine):

| Column | Description |
|--------|-------------|
| `timestamp` | Event time |
| `src_ip` | Source IP |
| `dst_ip` | Destination IP |
| `protocol` | e.g. TCP, UDP |
| `src_port` | Source port |
| `dst_port` | Destination port |
| `bytes` | Bytes transferred |
| `duration` | Connection duration |
| `status` | e.g. allowed, denied |
| `failed_logins` | Failed login count |
| `packets` | Packet count |

Missing columns are filled with safe defaults automatically. Column names are case-insensitive after loading.

## Setup and run

### Windows (easiest)

1. Clone or download this repository.
2. Put your CSV log file(s) in `network/`.
3. **First time:** double-click `first_time_setup.bat`
   - Creates `.venv`
   - Installs dependencies from `requirements.txt`
   - Runs the analyzer
4. **Later runs:** double-click `run.bat`
5. If several CSV files exist in `network/`, pick one by number or type the filename when prompted.

Progress bars appear in the console while loading, analyzing, and writing reports.

### Terminal (any OS)

From the project root:

```bash
# Create and activate a virtual environment (recommended)
python -m venv .venv

# Windows
.venv\Scripts\activate

# macOS / Linux
source .venv/bin/activate

pip install -r requirements.txt
```

Put your CSV files in `network/`, then run:

```bash
# Interactive: pick one file if multiple CSVs exist
python main.py

# Analyze a specific file (name only, must be in network/)
python main.py --file your_log.csv
```

### PyCharm

1. Open this folder as a project.
2. Set the project interpreter to `.venv` (create it with `python -m venv .venv` if needed).
3. Install dependencies: **Terminal →** `pip install -r requirements.txt`
4. Add CSV files to `network/`.
5. Run `main.py` with the same CLI options as above.

## Output

Each run creates a new folder under `reports/`:

- `reports/YYYY-MM-DD_HH-MM-SS/analysis_report.json` — machine-readable
- `reports/YYYY-MM-DD_HH-MM-SS/analysis_report.md` — human-readable (SOC workflow)
- `reports/YYYY-MM-DD_HH-MM-SS/analysis_report.html` — dashboard with charts, risk levels, and remediation steps

The console prints the exact path to the HTML report when analysis finishes.

## Analysis workflow

1. Select **one** CSV from `network/` (interactive menu or `--file`).
2. Normalize and validate columns; fill missing fields with defaults.
3. Encode categorical fields and prepare numeric features.
4. Train an unsupervised `IsolationForest` model on the loaded data.
5. Score each event and flag outliers as anomalies.
6. Attach risk reasons (e.g. brute-force patterns, sensitive ports, long sessions, packet floods, denied access).
7. Generate remediation steps per anomaly and export JSON, Markdown, and HTML reports.

## Note

This is a showcase IPS analytics project, not a production IDS/IPS. For real deployments, add SIEM integration, threat intelligence feeds, automated blocking, and model validation pipelines.
