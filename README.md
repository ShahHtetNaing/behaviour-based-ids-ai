# Behaviour-based Intrusion Prevention System (AI)

A simple showcase project for GitHub and LinkedIn.  
It reads real network log CSV files from the `network` folder, runs AI-based behavior anomaly detection, and writes detailed findings with remediation steps.

## What this project does

- Ingests one or many CSV network logs from `network/`
- Learns normal behavior using `IsolationForest` (unsupervised AI)
- Flags suspicious records as anomalies
- Explains why each anomaly is risky
- Generates detailed fix steps for analysts
- Exports reports to a new timestamped folder under `reports/` (example: `reports/2026-06-01_14-30-45/`)

## Folder structure

```text
behaviour-based-ips-ai/
├─ main.py
├─ requirements.txt
├─ network/
│  └─ sample_network_log.csv
├─ reports/
└─ ips_ai/
   ├─ __init__.py
   ├─ data_loader.py
   ├─ analyzer.py
   └─ reporting.py
```

## Expected CSV columns

Your real network log CSV should include these columns (extra columns are okay):

- `timestamp`
- `src_ip`
- `dst_ip`
- `protocol`
- `src_port`
- `dst_port`
- `bytes`
- `duration`
- `status`
- `failed_logins`
- `packets`

If some columns are missing, the project automatically fills safe defaults.

## Setup in PyCharm

1. Open this folder in PyCharm.
2. Create/select a Python interpreter (venv recommended).
3. Install dependencies:
   - `pip install -r requirements.txt`
4. Put your real CSV log files into `network/`.
5. Run:
   - `python main.py`
   - If multiple CSV files exist, choose one from the menu.
   - Or analyze one file directly:
     - `python main.py --file your_log.csv`

## Easiest run on Windows (no PyCharm config needed)

- First time: double-click `first_time_setup.bat`
  - Creates `.venv`
  - Installs dependencies
  - Runs analyzer
- Next runs: double-click `run.bat`
- You will see live progress bars while loading, analyzing, and generating reports.

## Output

After running, check:

After running, check the newest folder inside `reports/`:

- `reports/YYYY-MM-DD_HH-MM-SS/analysis_report.json` (machine-readable)
- `reports/YYYY-MM-DD_HH-MM-SS/analysis_report.md` (human-readable, for SOC workflow)
- `reports/YYYY-MM-DD_HH-MM-SS/analysis_report.html` (visual dashboard with charts, risk levels, and remediation steps)

## Deep analysis workflow used

1. Load all CSV logs from `network/`.
2. Normalize and validate columns.
3. Convert numeric features and encode categorical behavior.
4. Train unsupervised anomaly model on current dataset.
5. Score each event and detect outliers.
6. Attach detailed risk reasons:
   - brute-force behavior
   - sensitive service abuse
   - long connection anomalies
   - packet flood indicators
   - denied/failed access patterns
7. Generate step-by-step remediation actions per anomaly.

## Note

This is a showcase IPS analytics project.  
For production, you should add SIEM integration, threat intel feeds, automated blocking hooks, and validation pipelines.
