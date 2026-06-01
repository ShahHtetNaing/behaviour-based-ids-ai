import argparse
from pathlib import Path

from ips_ai.analyzer import BehaviourBasedIPS
from ips_ai.data_loader import choose_network_log_file, load_network_logs
from ips_ai.progress import ProgressTracker
from ips_ai.reporting import create_report_run_folder, export_reports


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Behaviour-based Intrusion Prevention System (AI log analyzer)"
    )
    parser.add_argument(
        "--file",
        dest="file_name",
        help="Analyze one CSV file from /network (example: --file firewall_log.csv)",
    )
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    project_root = Path(__file__).resolve().parent
    network_folder = project_root / "network"
    reports_root = project_root / "reports"

    progress = ProgressTracker()
    progress.start()

    try:
        if args.file_name:
            selected_name = args.file_name
            print(f"Analyzing selected file: {selected_name}")
            progress.set(2, f"Selected {selected_name}")
            logs_df = load_network_logs(
                network_folder,
                selected_names=[selected_name],
                progress=progress,
            )
        else:
            progress.set(1, "Waiting for file selection")
            selected_file = choose_network_log_file(network_folder)
            logs_df = load_network_logs(
                network_folder,
                selected_names=[selected_file.name],
                progress=progress,
            )

        progress.set(20, f"Loaded {len(logs_df):,} records")

        ips = BehaviourBasedIPS()
        analysis = ips.analyze(logs_df, progress=progress)

        report_run_folder = create_report_run_folder(reports_root)
        export_reports(analysis, report_run_folder, progress=progress)
    finally:
        progress.close()

    print("\nAnalysis complete.")
    print(f"Analyzed file(s): {', '.join(sorted(logs_df['source_file'].unique()))}")
    print(f"Anomalies found: {analysis['summary']['anomalies_found']}")
    print(f"Risk level: {analysis['summary']['risk_level']}")
    print(f"Reports saved to: {report_run_folder}")
    print(f"Open HTML report: {report_run_folder / 'analysis_report.html'}")


if __name__ == "__main__":
    main()
