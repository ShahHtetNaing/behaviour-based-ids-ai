from pathlib import Path
from typing import List, Optional

import pandas as pd

from ips_ai.progress import ProgressTracker


SUPPORTED_EXTENSIONS = {".csv"}


def _normalize_columns(frame: pd.DataFrame) -> pd.DataFrame:
    frame = frame.copy()
    frame.columns = [col.strip().lower() for col in frame.columns]
    return frame


def _required_defaults(frame: pd.DataFrame) -> pd.DataFrame:
    defaults = {
        "timestamp": "1970-01-01T00:00:00",
        "src_ip": "0.0.0.0",
        "dst_ip": "0.0.0.0",
        "protocol": "unknown",
        "src_port": 0,
        "dst_port": 0,
        "bytes": 0.0,
        "duration": 0.0,
        "status": "unknown",
        "failed_logins": 0.0,
        "packets": 0.0,
    }
    for column, default_value in defaults.items():
        if column not in frame.columns:
            frame[column] = default_value
    return frame


def list_network_log_files(network_folder: Path) -> List[Path]:
    if not network_folder.exists():
        raise FileNotFoundError(
            f"Network folder not found: {network_folder}. Create it and add CSV logs."
        )

    files = sorted(
        path
        for path in network_folder.iterdir()
        if path.is_file() and path.suffix.lower() in SUPPORTED_EXTENSIONS
    )
    if not files:
        raise FileNotFoundError(
            "No supported network log files found in /network. Add at least one CSV file."
        )
    return files


def _read_csv_files(files: List[Path], progress: Optional[ProgressTracker] = None) -> pd.DataFrame:
    frames = []
    chunk_size = 50_000

    for index, file_path in enumerate(files):
        chunks = []
        reader = pd.read_csv(file_path, chunksize=chunk_size)

        if progress:
            progress.set(5 + index * 5, f"Loading {file_path.name}")

        if progress:
            chunk_iter = progress.iterate(reader, desc=f"  Reading {file_path.name}", unit="chunks")
        else:
            chunk_iter = reader

        for chunk in chunk_iter:
            chunks.append(chunk)

        frame = pd.concat(chunks, ignore_index=True) if chunks else pd.read_csv(file_path)
        frame = _normalize_columns(frame)
        frame = _required_defaults(frame)
        frame["source_file"] = file_path.name
        frames.append(frame)

        if progress:
            progress.set(15 + index * 5, f"Loaded {len(frame):,} rows from {file_path.name}")

    return pd.concat(frames, ignore_index=True)


def resolve_selected_files(
    network_folder: Path,
    selected_names: Optional[List[str]] = None,
) -> List[Path]:
    available = list_network_log_files(network_folder)

    if not selected_names:
        return available

    lookup = {path.name.lower(): path for path in available}
    resolved: List[Path] = []
    missing: List[str] = []

    for name in selected_names:
        match = lookup.get(Path(name).name.lower())
        if match:
            resolved.append(match)
        else:
            missing.append(name)

    if missing:
        available_names = ", ".join(path.name for path in available)
        raise FileNotFoundError(
            f"File(s) not found in /network: {', '.join(missing)}. Available: {available_names}"
        )

    return resolved


def choose_network_log_file(network_folder: Path) -> Path:
    files = list_network_log_files(network_folder)

    if len(files) == 1:
        print(f"Using log file: {files[0].name}")
        return files[0]

    print("\nMultiple CSV files found in /network:")
    for index, file_path in enumerate(files, start=1):
        print(f"  {index}. {file_path.name}")

    while True:
        choice = input("\nEnter file number to analyze (or type file name): ").strip()
        if not choice:
            print("Please enter a number or file name.")
            continue

        if choice.isdigit():
            selected_index = int(choice)
            if 1 <= selected_index <= len(files):
                selected = files[selected_index - 1]
                print(f"Selected: {selected.name}")
                return selected
            print(f"Please enter a number between 1 and {len(files)}.")
            continue

        match = next((path for path in files if path.name.lower() == choice.lower()), None)
        if match:
            print(f"Selected: {match.name}")
            return match

        print("Invalid choice. Try again.")


def load_network_logs(
    network_folder: Path,
    selected_names: Optional[List[str]] = None,
    progress: Optional[ProgressTracker] = None,
) -> pd.DataFrame:
    files = resolve_selected_files(network_folder, selected_names)
    frame = _read_csv_files(files, progress=progress)
    if frame.empty:
        raise ValueError("Loaded files are empty. Please provide valid network logs.")
    return frame