import html
import json
from datetime import datetime, timezone
from typing import Any, Dict, List

HTML_DETAIL_LIMIT = 50


def _esc(value: Any) -> str:
    return html.escape(str(value))


def _risk_class(level: str) -> str:
    return level.lower()


def _stat_bar(label: str, value: int, total: int, color: str) -> str:
    pct = 0 if total == 0 else round((value / total) * 100, 1)
    return f"""
    <div class="stat-row">
      <div class="stat-label"><span>{_esc(label)}</span><strong>{value} ({pct}%)</strong></div>
      <div class="stat-track"><div class="stat-fill {color}" style="width:{pct}%"></div></div>
    </div>
    """


def _anomaly_cards(anomalies: List[Dict[str, Any]]) -> str:
    if not anomalies:
        return '<div class="empty">No anomalies detected. Your traffic matched the learned baseline.</div>'

    cards = []
    for idx, item in enumerate(anomalies, start=1):
        reasons = "".join(f"<li>{_esc(r)}</li>" for r in item["risk_reasons"])
        steps = "".join(f"<li>{_esc(s)}</li>" for s in item["recommended_fix_steps"])
        cards.append(
            f"""
            <article class="anomaly-card risk-{_risk_class(item['risk_level'])}">
              <header>
                <h3>Anomaly #{idx} · {_esc(item['impact_category'])}</h3>
                <span class="badge risk-{_risk_class(item['risk_level'])}">{_esc(item['risk_level'])} RISK</span>
              </header>
              <p class="what"><strong>What is it?</strong> {_esc(item['what_is_it'])}</p>
              <div class="grid-meta">
                <div><span>Time</span><p>{_esc(item['timestamp'])}</p></div>
                <div><span>Source → Destination</span><p>{_esc(item['src_ip'])} → {_esc(item['dst_ip'])}</p></div>
                <div><span>Protocol / Port</span><p>{_esc(item['protocol'])} / {_esc(item['dst_port'])}</p></div>
                <div><span>AI Score</span><p>{item['anomaly_score']:.4f}</p></div>
                <div><span>Bytes / Packets</span><p>{item['bytes']:.0f} / {item['packets']:.0f}</p></div>
                <div><span>Log File</span><p>{_esc(item['source_file'])}</p></div>
              </div>
              <div class="impact-box current">
                <h4>Current impact</h4>
                <p>{_esc(item['current_impact'])}</p>
              </div>
              <div class="impact-box future">
                <h4>Future impact if unresolved</h4>
                <p>{_esc(item['future_impact'])}</p>
              </div>
              <div class="two-col">
                <div>
                  <h4>Why flagged</h4>
                  <ul>{reasons}</ul>
                </div>
                <div>
                  <h4>How to resolve (step-by-step)</h4>
                  <ol>{steps}</ol>
                </div>
              </div>
            </article>
            """
        )
    return "\n".join(cards)


def build_html_report(analysis: Dict[str, Any]) -> str:
    summary = analysis["summary"]
    total = summary["records_processed"]
    anomalies = summary["anomalies_found"]
    normal = summary.get("normal_records", total - anomalies)
    risk_breakdown = summary.get("risk_breakdown", {})
    impact_breakdown = summary.get("impact_breakdown", {})

    all_anomalies = analysis["anomalies"]
    display_anomalies = all_anomalies[:HTML_DETAIL_LIMIT]
    detail_note = ""
    if len(all_anomalies) > HTML_DETAIL_LIMIT:
        detail_note = (
            f'<p class="detail-note">Showing top {HTML_DETAIL_LIMIT} highest-risk anomalies '
            f"of {len(all_anomalies)} total. Full data is in <code>analysis_report.json</code>.</p>"
        )

    risk_labels = list(risk_breakdown.keys())
    risk_values = list(risk_breakdown.values())
    impact_labels = list(impact_breakdown.keys()) or ["No anomalies"]
    impact_values = list(impact_breakdown.values()) or [1]

    generated = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")

    stat_bars = "\n".join(
        [
            _stat_bar("Normal traffic", normal, total, "bar-safe"),
            _stat_bar("Anomalies", anomalies, total, "bar-danger"),
            _stat_bar("Critical risk events", risk_breakdown.get("CRITICAL", 0), max(anomalies, 1), "bar-critical"),
            _stat_bar("High risk events", risk_breakdown.get("HIGH", 0), max(anomalies, 1), "bar-high"),
        ]
    )

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1.0" />
  <title>IPS AI Security Report</title>
  <script src="https://cdn.jsdelivr.net/npm/chart.js@4.4.1/dist/chart.umd.min.js"></script>
  <style>
    :root {{
      --bg: #0b1220;
      --panel: #121a2b;
      --panel-2: #1a2438;
      --text: #e8eefc;
      --muted: #9fb0d0;
      --accent: #4f8cff;
      --safe: #2ecc71;
      --warn: #f39c12;
      --high: #ff7a45;
      --critical: #ff4d6d;
      --border: #2a3754;
    }}
    * {{ box-sizing: border-box; }}
    body {{
      margin: 0;
      font-family: "Segoe UI", Tahoma, sans-serif;
      background: radial-gradient(circle at top, #15213a, var(--bg));
      color: var(--text);
      line-height: 1.5;
    }}
    .wrap {{ max-width: 1200px; margin: 0 auto; padding: 28px; }}
    .hero {{
      background: linear-gradient(135deg, #1f2f52, #16233d);
      border: 1px solid var(--border);
      border-radius: 16px;
      padding: 24px;
      margin-bottom: 20px;
      box-shadow: 0 10px 30px rgba(0,0,0,.25);
    }}
    .hero h1 {{ margin: 0 0 8px; font-size: 1.8rem; }}
    .hero p {{ margin: 0; color: var(--muted); }}
    .risk-pill {{
      display: inline-block;
      margin-top: 14px;
      padding: 8px 14px;
      border-radius: 999px;
      font-weight: 700;
      letter-spacing: .04em;
      background: #223252;
      border: 1px solid var(--border);
    }}
    .risk-pill.critical {{ color: #fff; background: var(--critical); }}
    .risk-pill.high {{ color: #fff; background: var(--high); }}
    .risk-pill.medium {{ color: #111; background: var(--warn); }}
    .risk-pill.low {{ color: #111; background: var(--safe); }}
    .kpis {{
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(180px, 1fr));
      gap: 14px;
      margin: 20px 0;
    }}
    .kpi {{
      background: var(--panel);
      border: 1px solid var(--border);
      border-radius: 12px;
      padding: 16px;
    }}
    .kpi span {{ color: var(--muted); font-size: .85rem; }}
    .kpi h2 {{ margin: 6px 0 0; font-size: 1.6rem; }}
    .panel {{
      background: var(--panel);
      border: 1px solid var(--border);
      border-radius: 14px;
      padding: 18px;
      margin-bottom: 18px;
    }}
    .panel h2 {{ margin-top: 0; font-size: 1.15rem; }}
    .stat-row {{ margin-bottom: 12px; }}
    .stat-label {{ display: flex; justify-content: space-between; margin-bottom: 6px; color: var(--muted); }}
    .stat-track {{ height: 10px; background: #0d1424; border-radius: 999px; overflow: hidden; }}
    .stat-fill {{ height: 100%; border-radius: 999px; }}
    .bar-safe {{ background: var(--safe); }}
    .bar-danger {{ background: var(--critical); }}
    .bar-critical {{ background: #b8002f; }}
    .bar-high {{ background: var(--high); }}
    .charts {{
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(280px, 1fr));
      gap: 16px;
    }}
    .chart-box {{
      background: var(--panel-2);
      border: 1px solid var(--border);
      border-radius: 12px;
      padding: 12px;
      min-height: 320px;
    }}
    .anomaly-card {{
      background: var(--panel);
      border: 1px solid var(--border);
      border-left: 5px solid var(--accent);
      border-radius: 12px;
      padding: 16px;
      margin-bottom: 14px;
    }}
    .anomaly-card.risk-critical {{ border-left-color: var(--critical); }}
    .anomaly-card.risk-high {{ border-left-color: var(--high); }}
    .anomaly-card.risk-medium {{ border-left-color: var(--warn); }}
    .anomaly-card.risk-low {{ border-left-color: var(--safe); }}
    .anomaly-card header {{
      display: flex; justify-content: space-between; align-items: center; gap: 10px;
    }}
    .anomaly-card h3 {{ margin: 0; font-size: 1.05rem; }}
    .badge {{
      padding: 4px 10px; border-radius: 999px; font-size: .75rem; font-weight: 700;
      background: #223252; border: 1px solid var(--border);
    }}
    .badge.risk-critical {{ background: var(--critical); color: #fff; }}
    .badge.risk-high {{ background: var(--high); color: #fff; }}
    .badge.risk-medium {{ background: var(--warn); color: #111; }}
    .badge.risk-low {{ background: var(--safe); color: #111; }}
    .what {{ margin: 12px 0; }}
    .grid-meta {{
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(170px, 1fr));
      gap: 10px;
      margin-bottom: 12px;
    }}
    .grid-meta span {{ color: var(--muted); font-size: .8rem; }}
    .grid-meta p {{ margin: 2px 0 0; }}
    .impact-box {{
      background: #0f1728;
      border: 1px solid var(--border);
      border-radius: 10px;
      padding: 10px 12px;
      margin-bottom: 10px;
    }}
    .impact-box h4 {{ margin: 0 0 6px; font-size: .92rem; }}
    .impact-box.current h4 {{ color: #7ec8ff; }}
    .impact-box.future h4 {{ color: #ffb4c0; }}
    .two-col {{
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(260px, 1fr));
      gap: 12px;
    }}
    .two-col ul, .two-col ol {{ margin: 6px 0 0; padding-left: 18px; }}
    .empty {{
      padding: 20px;
      border: 1px dashed var(--border);
      border-radius: 10px;
      color: var(--muted);
      text-align: center;
    }}
    .detail-note {{
      color: var(--muted);
      background: #0f1728;
      border: 1px solid var(--border);
      border-radius: 8px;
      padding: 10px 12px;
      margin-bottom: 12px;
    }}
    footer {{ color: var(--muted); font-size: .85rem; text-align: center; margin-top: 10px; }}
  </style>
</head>
<body>
  <div class="wrap">
    <section class="hero">
      <h1>Behaviour-Based IPS · AI Security Report</h1>
      <p>Generated on {_esc(generated)}</p>
      <span class="risk-pill {_risk_class(summary['risk_level'])}">Overall Risk: {_esc(summary['risk_level'])}</span>
    </section>

    <section class="kpis">
      <div class="kpi"><span>Records processed</span><h2>{total}</h2></div>
      <div class="kpi"><span>Anomalies detected</span><h2>{anomalies}</h2></div>
      <div class="kpi"><span>Normal records</span><h2>{normal}</h2></div>
      <div class="kpi"><span>Anomaly ratio</span><h2>{summary['anomaly_ratio_percent']}%</h2></div>
    </section>

    <section class="panel">
      <h2>Traffic statistics</h2>
      {stat_bars}
    </section>

    <section class="panel charts">
      <div class="chart-box">
        <h2>Risk level distribution</h2>
        <canvas id="riskChart"></canvas>
      </div>
      <div class="chart-box">
        <h2>Impact category distribution</h2>
        <canvas id="impactChart"></canvas>
      </div>
    </section>

    <section class="panel">
      <h2>Detailed anomalies & remediation</h2>
      {detail_note}
      {_anomaly_cards(display_anomalies)}
    </section>

    <footer>Behaviour-based Intrusion Prevention System · Showcase report</footer>
  </div>

  <script>
    const palette = ["#4f8cff", "#ff4d6d", "#ff7a45", "#f39c12", "#2ecc71", "#9b59b6"];
    const commonOptions = {{
      responsive: true,
      plugins: {{
        legend: {{ position: "bottom", labels: {{ color: "#dbe7ff" }} }}
      }}
    }};

    new Chart(document.getElementById("riskChart"), {{
      type: "pie",
      data: {{
        labels: {json.dumps(risk_labels)},
        datasets: [{{
          data: {json.dumps(risk_values)},
          backgroundColor: palette
        }}]
      }},
      options: commonOptions
    }});

    new Chart(document.getElementById("impactChart"), {{
      type: "doughnut",
      data: {{
        labels: {json.dumps(impact_labels)},
        datasets: [{{
          data: {json.dumps(impact_values)},
          backgroundColor: palette
        }}]
      }},
      options: commonOptions
    }});
  </script>
</body>
</html>
"""
