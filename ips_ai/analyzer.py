from dataclasses import dataclass
from typing import Any, Dict, Optional

import numpy as np
import pandas as pd
from sklearn.compose import ColumnTransformer
from sklearn.ensemble import IsolationForest
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import OneHotEncoder, StandardScaler

from ips_ai.progress import ProgressTracker


@dataclass
class BehaviourBasedIPS:
    contamination: float = 0.08
    random_state: int = 42

    def _build_pipeline(self, frame: pd.DataFrame) -> Pipeline:
        numeric_features = ["src_port", "dst_port", "bytes", "duration", "failed_logins", "packets"]
        categorical_features = ["protocol", "status", "src_ip", "dst_ip", "source_file"]

        for col in numeric_features:
            frame[col] = pd.to_numeric(frame[col], errors="coerce").fillna(0.0)
        for col in categorical_features:
            frame[col] = frame[col].astype(str).fillna("unknown")

        preprocess = ColumnTransformer(
            transformers=[
                ("num", Pipeline([("scale", StandardScaler())]), numeric_features),
                ("cat", OneHotEncoder(handle_unknown="ignore"), categorical_features),
            ]
        )

        model = IsolationForest(
            n_estimators=250,
            contamination=self.contamination,
            random_state=self.random_state,
        )

        return Pipeline([("preprocess", preprocess), ("model", model)])

    def _impact_category(self, reasons: list[str]) -> str:
        joined = " ".join(reasons).lower()
        if "brute-force" in joined:
            return "Credential Attack"
        if "packet flood" in joined:
            return "Availability / DoS"
        if "sensitive service" in joined:
            return "Lateral Movement / Exfiltration"
        if "long-lived" in joined:
            return "Persistent Access"
        if "failed/denied" in joined:
            return "Unauthorized Access"
        return "Behavioral Anomaly"

    def _row_risk_level(self, row: pd.Series, score: float) -> str:
        if row["failed_logins"] >= 10 or row["packets"] > 20000 or score >= 0.35:
            return "CRITICAL"
        if row["failed_logins"] >= 5 or row["bytes"] > 800000 or score >= 0.22:
            return "HIGH"
        if score >= 0.12 or row["duration"] > 1800:
            return "MEDIUM"
        return "LOW"

    def _what_is_it(self, reasons: list[str], row: pd.Series) -> str:
        category = self._impact_category(reasons)
        return (
            f"A {category.lower()} event was detected from {row['src_ip']} targeting "
            f"{row['dst_ip']}:{int(row['dst_port'])} over {row['protocol'].upper()}."
        )

    def _current_impact(self, reasons: list[str], row: pd.Series) -> str:
        impacts = []
        if row["failed_logins"] >= 5:
            impacts.append("Active authentication pressure on exposed services.")
        if row["dst_port"] in {22, 23, 3389, 445}:
            impacts.append("Critical admin/remote services are being targeted now.")
        if row["packets"] > 10000:
            impacts.append("Network performance degradation and service instability may occur.")
        if row["status"].lower() in {"failed", "denied", "reset"}:
            impacts.append("Access control is already rejecting suspicious sessions.")
        if not impacts:
            impacts.append("Traffic deviates from learned baseline and may indicate early-stage compromise.")
        return " ".join(impacts)

    def _future_impact(self, reasons: list[str], row: pd.Series) -> str:
        category = self._impact_category(reasons)
        mapping = {
            "Credential Attack": "Account takeover, privilege escalation, and ransomware staging.",
            "Availability / DoS": "Extended outages, SLA breaches, and recovery costs.",
            "Lateral Movement / Exfiltration": "Data theft, command-and-control channels, and internal spread.",
            "Persistent Access": "Backdoor persistence and undetected long-term surveillance.",
            "Unauthorized Access": "Policy violations escalating to full environment compromise.",
            "Behavioral Anomaly": "Missed early warning signals leading to larger incident response effort.",
        }
        base = mapping.get(category, "Increased incident scope and forensic complexity.")
        if row["failed_logins"] >= 5:
            return f"{base} Without action, attackers may gain valid credentials within hours."
        return f"{base} If ignored, this pattern often repeats and expands to additional hosts."

    def _calculate_row_risk(self, row: pd.Series) -> Dict[str, Any]:
        reasons = []
        if row["failed_logins"] >= 5:
            reasons.append("Brute-force login pattern")
        if row["dst_port"] in {22, 23, 3389, 445} and row["bytes"] > 500000:
            reasons.append("Sensitive service with unusually high transfer")
        if row["duration"] > 3600:
            reasons.append("Long-lived connection outside normal behavior")
        if row["packets"] > 10000:
            reasons.append("Packet flood signature")
        if row["status"].lower() in {"failed", "denied", "reset"}:
            reasons.append("Failed/denied access pattern")
        if not reasons:
            reasons.append("Statistical outlier against learned baseline")

        score = float(row["anomaly_score"])
        risk_level = self._row_risk_level(row, score)
        impact_category = self._impact_category(reasons)

        return {
            "timestamp": str(row["timestamp"]),
            "src_ip": row["src_ip"],
            "dst_ip": row["dst_ip"],
            "protocol": row["protocol"],
            "dst_port": int(row["dst_port"]),
            "bytes": float(row["bytes"]),
            "duration": float(row["duration"]),
            "failed_logins": float(row["failed_logins"]),
            "packets": float(row["packets"]),
            "source_file": row["source_file"],
            "anomaly_score": score,
            "risk_level": risk_level,
            "impact_category": impact_category,
            "what_is_it": self._what_is_it(reasons, row),
            "current_impact": self._current_impact(reasons, row),
            "future_impact": self._future_impact(reasons, row),
            "risk_reasons": reasons,
            "recommended_fix_steps": [
                "Validate whether this traffic is expected by checking asset owner and change logs.",
                "If unexpected, isolate the source host from critical network segments immediately.",
                "Block or rate-limit suspicious source IP and destination port on firewall/IPS.",
                "Force password reset and enable MFA if repeated login failures are present.",
                "Run endpoint malware scan and review active processes on the source host.",
                "Add a detection rule for this behavior pattern and monitor for recurrence for 72 hours.",
            ],
        }

    def analyze(
        self,
        frame: pd.DataFrame,
        progress: Optional[ProgressTracker] = None,
    ) -> Dict[str, Any]:
        working = frame.copy()

        if progress:
            progress.set(25, "Preparing AI features")

        pipeline = self._build_pipeline(working)

        if progress:
            progress.set(35, "Training AI model")

        pipeline.fit(working)

        if progress:
            progress.set(55, "Scoring network traffic")

        transformed = pipeline.named_steps["preprocess"].transform(working)
        raw_predictions = pipeline.named_steps["model"].predict(transformed)
        scores = pipeline.named_steps["model"].decision_function(transformed)
        working["is_anomaly"] = np.where(raw_predictions == -1, 1, 0)
        working["anomaly_score"] = -scores

        anomalies = working[working["is_anomaly"] == 1].copy()
        anomalies = anomalies.sort_values(by="anomaly_score", ascending=False)

        if progress:
            progress.set(60, f"Analyzing {len(anomalies):,} anomalies")

        details = []
        row_iter = (
            progress.iterate(
                anomalies.iterrows(),
                desc="  Building anomaly details",
                total=len(anomalies),
            )
            if progress
            else anomalies.iterrows()
        )
        for _, row in row_iter:
            details.append(self._calculate_row_risk(row))

        if progress:
            progress.set(85, "Calculating risk summary")

        risk_counts = {"LOW": 0, "MEDIUM": 0, "HIGH": 0, "CRITICAL": 0}
        impact_counts: Dict[str, int] = {}
        for item in details:
            risk_counts[item["risk_level"]] = risk_counts.get(item["risk_level"], 0) + 1
            cat = item["impact_category"]
            impact_counts[cat] = impact_counts.get(cat, 0) + 1

        overall_risk = "LOW"
        if risk_counts["CRITICAL"] > 0 or risk_counts["HIGH"] >= 3:
            overall_risk = "CRITICAL"
        elif risk_counts["HIGH"] > 0 or len(details) >= 5:
            overall_risk = "HIGH"
        elif len(details) >= 2:
            overall_risk = "MEDIUM"

        normal_count = int(len(working) - len(details))

        return {
            "summary": {
                "records_processed": int(len(working)),
                "anomalies_found": int(len(details)),
                "normal_records": normal_count,
                "anomaly_ratio_percent": round((len(details) / len(working)) * 100, 2),
                "risk_level": overall_risk,
                "risk_breakdown": risk_counts,
                "impact_breakdown": impact_counts,
            },
            "anomalies": details,
        }
