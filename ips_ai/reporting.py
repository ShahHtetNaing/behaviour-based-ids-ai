import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Optional

from ips_ai.html_report import build_html_report
from ips_ai.progress import ProgressTracker


def _build_markdown(analysis: Dict[str, Any]) -> str:
    summary = analysis["summary"]
    lines = [
        "# Behaviour-Based Intrusion Prevention System Report",
        "",
        f"- Generated at: {datetime.now(timezone.utc).isoformat()}",
        f"- Records processed: {summary['records_processed']}",
        f"- Anomalies found: {summary['anomalies_found']}",
        f"- Anomaly ratio (%): {summary['anomaly_ratio_percent']}",
        f"- Risk level: {summary['risk_level']}",
        "",
        "## Detailed Anomalies",
        "",
    ]

    if not analysis["anomalies"]:
        lines.append("No anomalies detected.")
        return "\n".join(lines)

    for idx, anomaly in enumerate(analysis["anomalies"], start=1):
        lines.append(f"### Anomaly {idx}")
        lines.append(f"- Timestamp: {anomaly['timestamp']}")
        lines.append(f"- Source: {anomaly['src_ip']} -> Destination: {anomaly['dst_ip']}")
        lines.append(f"- Protocol/Port: {anomaly['protocol']} / {anomaly['dst_port']}")
        lines.append(f"- Volume: bytes={anomaly['bytes']}, packets={anomaly['packets']}")
        lines.append(f"- Duration: {anomaly['duration']} seconds")
        lines.append(f"- Failed logins: {anomaly['failed_logins']}")
        lines.append(f"- Source file: {anomaly['source_file']}")
        lines.append(f"- AI anomaly score: {round(anomaly['anomaly_score'], 6)}")
        lines.append(f"- Risk level: {anomaly.get('risk_level', 'N/A')}")
        lines.append(f"- Impact category: {anomaly.get('impact_category', 'N/A')}")
        lines.append(f"- What is it: {anomaly.get('what_is_it', 'N/A')}")
        lines.append(f"- Current impact: {anomaly.get('current_impact', 'N/A')}")
        lines.append(f"- Future impact: {anomaly.get('future_impact', 'N/A')}")
        lines.append("- Why this is suspicious:")
        for reason in anomaly["risk_reasons"]:
            lines.append(f"  - {reason}")
        lines.append("- How to solve this (step-by-step):")
        for step in anomaly["recommended_fix_steps"]:
            lines.append(f"  - {step}")
        lines.append("")

    return "\n".join(lines)


def create_report_run_folder(reports_root: Path) -> Path:
    reports_root.mkdir(parents=True, exist_ok=True)
    base_name = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
    run_folder = reports_root / base_name
    counter = 1

    while run_folder.exists():
        run_folder = reports_root / f"{base_name}_{counter}"
        counter += 1

    run_folder.mkdir(parents=True, exist_ok=True)
    return run_folder


def export_reports(
    analysis: Dict[str, Any],
    reports_folder: Path,
    progress: Optional[ProgressTracker] = None,
) -> Path:
    if progress:
        progress.set(90, "Writing JSON report")

    reports_folder.mkdir(parents=True, exist_ok=True)

    json_report = reports_folder / "analysis_report.json"
    md_report = reports_folder / "analysis_report.md"
    html_report = reports_folder / "analysis_report.html"

    json_report.write_text(json.dumps(analysis, indent=2), encoding="utf-8")

    if progress:
        progress.set(94, "Writing Markdown report")

    md_report.write_text(_build_markdown(analysis), encoding="utf-8")

    if progress:
        progress.set(97, "Writing HTML dashboard")

    html_report.write_text(build_html_report(analysis), encoding="utf-8")
    return reports_folder
