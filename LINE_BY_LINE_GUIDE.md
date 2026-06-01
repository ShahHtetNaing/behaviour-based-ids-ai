# Line-by-Line Code Guide

This file explains **why each library is used** and **what each major line/block does**.

## Libraries and why used

- `pandas`: table-like log processing (CSV parsing, cleaning, transformations)
- `numpy`: vectorized numerical operations (`np.where` for fast label assignment)
- `scikit-learn`:
  - `IsolationForest`: unsupervised anomaly detection model
  - `ColumnTransformer`: apply different preprocessing to numeric vs categorical data
  - `StandardScaler`: normalize numeric ranges
  - `OneHotEncoder`: convert categorical fields (protocol/IP/status) into machine features
  - `Pipeline`: clean preprocessing + model execution chain
- `python-dateutil`: common date parsing helper dependency for many timestamp workflows (kept for future extension)

---

## `main.py`

- `from pathlib import Path`  
  Uses robust cross-platform path handling (important in PyCharm + Windows).
- `from ips_ai.analyzer import BehaviourBasedIPS`  
  Imports the AI engine class.
- `from ips_ai.data_loader import load_network_logs`  
  Imports network file loading function.
- `from ips_ai.reporting import export_reports`  
  Imports report writer function.
- `def main() -> None:`  
  Entry-point function for clean execution.
- `project_root = Path(__file__).resolve().parent`  
  Detects the current project folder automatically.
- `network_folder = project_root / "network"`  
  Sets required user upload folder.
- `reports_folder = project_root / "reports"`  
  Sets output folder.
- `logs_df = load_network_logs(network_folder)`  
  Reads user-provided network logs into DataFrame.
- `ips = BehaviourBasedIPS()`  
  Creates AI detector with default settings.
- `analysis = ips.analyze(logs_df)`  
  Runs deep behavior anomaly analysis.
- `export_reports(analysis, reports_folder)`  
  Saves JSON + Markdown detailed reports.
- `print(...)` lines  
  Show analyst-friendly run summary in terminal.
- `if __name__ == "__main__": main()`  
  Runs script only when file is executed directly.

---

## `ips_ai/data_loader.py`

- `SUPPORTED_EXTENSIONS = {".csv"}`  
  Restricts file type for predictable parsing.
- `_normalize_columns(...)`  
  Standardizes column names to lowercase; avoids casing bugs.
- `_required_defaults(...)`  
  Ensures required fields exist; adds safe defaults if missing.
- `_read_csv_files(files)`  
  Loops through each CSV, normalizes, fills defaults, tags source filename.
- `load_network_logs(network_folder)`  
  Main loader:
  - validates folder existence
  - validates that supported files exist
  - loads and merges logs
  - validates not empty

Why this design: real-life logs are inconsistent; this creates a reliable input contract for the model.

---

## `ips_ai/analyzer.py`

- `@dataclass class BehaviourBasedIPS`  
  Simple config container for model parameters.
- `contamination`  
  Estimated fraction of anomalies in dataset.
- `_build_pipeline(frame)`  
  Creates ML preprocessing + model stack:
  - numeric features: ports, bytes, duration, failed logins, packets
  - categorical features: protocol, status, source/destination IP, source file
  - casts numeric fields safely (`to_numeric(...).fillna(0.0)`)
  - casts categoricals to string
  - builds `ColumnTransformer` to scale numeric and one-hot encode categorical
  - configures `IsolationForest` model
  - returns full `Pipeline`

Why this code: behavior anomaly detection needs both numeric and categorical patterns.

- `_calculate_row_risk(row)`  
  Converts a flagged row into SOC-friendly explanation:
  - checks brute-force indicator (`failed_logins >= 5`)
  - checks sensitive service high transfer (`22, 23, 3389, 445`)
  - checks very long sessions (`duration > 3600`)
  - checks potential flood (`packets > 10000`)
  - checks failed/denied status
  - fallback reason if only statistical outlier
  - adds remediation steps

Why this code: model output alone is not enough; analysts need interpretation + actions.

- `analyze(frame)`  
  Full execution method:
  - copies input
  - fits pipeline on logs
  - predicts outlier labels (`-1` anomaly, `1` normal)
  - computes anomaly score using `decision_function`
  - flips sign (`-scores`) so higher = more suspicious
  - filters anomalies, sorts by severity
  - builds detailed records per anomaly
  - assigns overall risk level based on anomaly count
  - returns structured dict

Why this code: this is the end-to-end AI analysis path from raw logs to actionable intelligence.

---

## `ips_ai/reporting.py`

- `_build_markdown(analysis)`  
  Builds readable SOC report:
  - summary section
  - anomaly-by-anomaly details
  - explicit “why suspicious” list
  - explicit “how to solve step-by-step” list

- `export_reports(analysis, reports_folder)`  
  Creates folder and writes:
  - `analysis_report.json` for integrations/automation
  - `analysis_report.md` for humans/presentations

Why this code: technical + non-technical audiences need different report formats.

---

## How to use with real network logs

1. Export network logs to CSV from your source (firewall/SIEM/IDS/router).
2. Ensure columns map to expected names in `README.md`.
3. Place file(s) in `network/`.
4. Run `python main.py`.
5. Open `reports/analysis_report.md`.
6. For each anomaly, follow the listed remediation steps.

---

## Suggested GitHub + LinkedIn showcase angle

- “Built an AI-powered behavior-based IPS analyzer with unsupervised anomaly detection.”
- “Supports real network log uploads and auto-generates SOC-style remediation reports.”
- “Focused on explainability: not just anomaly flags, but detailed risk reasons and response steps.”
