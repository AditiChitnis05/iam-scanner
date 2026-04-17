"""
Reporter: Terminal summary + JSON report + optional HTML report
"""

import json
from datetime import datetime


SEVERITY_ORDER = {"HIGH": 0, "MEDIUM": 1, "LOW": 2, "ERROR": 3}
SEVERITY_EMOJI = {"HIGH": "🔴", "MEDIUM": "🟡", "LOW": "🔵", "ERROR": "⚠️"}


def print_summary(findings):
    if not findings:
        print("\n✅ No misconfigurations found! Your AWS IAM config looks clean.\n")
        return

    # Count by severity
    counts = {"HIGH": 0, "MEDIUM": 0, "LOW": 0, "ERROR": 0}
    for f in findings:
        sev = f.get("severity", "ERROR")
        counts[sev] = counts.get(sev, 0) + 1

    print(f"\n{'FINDING':<35} {'SEVERITY':<10} {'RESOURCE':<35} ")
    print("-" * 85)

    sorted_findings = sorted(findings, key=lambda x: SEVERITY_ORDER.get(x.get("severity", "ERROR"), 99))
    for f in sorted_findings:
        sev = f.get("severity", "?")
        emoji = SEVERITY_EMOJI.get(sev, "")
        check = f.get("check", "")[:33]
        resource = f.get("resource", "")[:33]
        print(f"{check:<35} {emoji} {sev:<8} {resource:<35}")

    print("-" * 85)
    print(f"\n📊 Summary:  🔴 HIGH: {counts['HIGH']}   🟡 MEDIUM: {counts['MEDIUM']}   🔵 LOW: {counts['LOW']}")

    if counts["HIGH"] > 0:
        print("⚠️  Action required — HIGH severity findings should be remediated immediately.")
    print()


def generate_report(findings, output_file="report.json", html=False):
    timestamp = datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ")

    report = {
        "scan_timestamp": timestamp,
        "total_findings": len(findings),
        "summary": {
            "HIGH": sum(1 for f in findings if f.get("severity") == "HIGH"),
            "MEDIUM": sum(1 for f in findings if f.get("severity") == "MEDIUM"),
            "LOW": sum(1 for f in findings if f.get("severity") == "LOW"),
            "ERROR": sum(1 for f in findings if f.get("severity") == "ERROR"),
        },
        "findings": sorted(findings, key=lambda x: SEVERITY_ORDER.get(x.get("severity", "ERROR"), 99))
    }

    # JSON report
    with open(output_file, "w") as f:
        json.dump(report, f, indent=2)
    print(f"📄 JSON report saved → {output_file}")

    # HTML report
    if html:
        html_file = output_file.replace(".json", ".html")
        _generate_html(report, html_file)
        print(f"🌐 HTML report saved → {html_file}")


def _generate_html(report, filename):
    color_map = {"HIGH": "#e74c3c", "MEDIUM": "#f39c12", "LOW": "#3498db", "ERROR": "#888"}
    bg_map = {"HIGH": "#fdf2f2", "MEDIUM": "#fefaf0", "LOW": "#f0f6ff", "ERROR": "#f9f9f9"}

    rows = ""
    for f in report["findings"]:
        sev = f.get("severity", "ERROR")
        color = color_map.get(sev, "#888")
        bg = bg_map.get(sev, "#fff")
        rows += f"""
        <tr style="background:{bg}">
            <td><span style="color:{color};font-weight:bold">{sev}</span></td>
            <td><code>{f.get('check','')}</code></td>
            <td>{f.get('resource_type','')}</td>
            <td><strong>{f.get('resource','')}</strong></td>
            <td>{f.get('message','')}</td>
            <td style="color:#27ae60">{f.get('recommendation','')}</td>
        </tr>"""

    s = report["summary"]
    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>IAM Misconfiguration Scan Report</title>
<style>
  body {{ font-family: Arial, sans-serif; margin: 40px; background: #f8f9fa; color: #222; }}
  h1 {{ color: #1a1a2e; }}
  .meta {{ color: #555; margin-bottom: 30px; font-size: 0.95em; }}
  .summary {{ display: flex; gap: 20px; margin-bottom: 30px; }}
  .badge {{ padding: 14px 24px; border-radius: 8px; font-size: 1.1em; font-weight: bold; }}
  .high   {{ background: #fdf2f2; color: #e74c3c; border: 1px solid #e74c3c; }}
  .medium {{ background: #fefaf0; color: #f39c12; border: 1px solid #f39c12; }}
  .low    {{ background: #f0f6ff; color: #3498db; border: 1px solid #3498db; }}
  table {{ width: 100%; border-collapse: collapse; background: white; border-radius: 8px; overflow: hidden; box-shadow: 0 2px 8px rgba(0,0,0,0.07); }}
  th {{ background: #1a1a2e; color: white; padding: 12px 14px; text-align: left; font-size: 0.9em; }}
  td {{ padding: 11px 14px; border-bottom: 1px solid #eee; font-size: 0.88em; vertical-align: top; }}
  tr:last-child td {{ border-bottom: none; }}
  code {{ background: #f0f0f0; padding: 2px 6px; border-radius: 4px; font-size: 0.85em; }}
  footer {{ margin-top: 30px; color: #aaa; font-size: 0.8em; }}
</style>
</head>
<body>
<h1>🔐 IAM Misconfiguration Scan Report</h1>
<div class="meta">
  Scan Time: {report['scan_timestamp']} &nbsp;|&nbsp; Total Findings: <strong>{report['total_findings']}</strong>
</div>
<div class="summary">
  <div class="badge high">🔴 HIGH &nbsp; {s['HIGH']}</div>
  <div class="badge medium">🟡 MEDIUM &nbsp; {s['MEDIUM']}</div>
  <div class="badge low">🔵 LOW &nbsp; {s['LOW']}</div>
</div>
<table>
  <thead>
    <tr>
      <th>Severity</th><th>Check</th><th>Type</th>
      <th>Resource</th><th>Finding</th><th>Recommendation</th>
    </tr>
  </thead>
  <tbody>{rows}</tbody>
</table>
<footer>Generated by IAM Misconfiguration Scanner &mdash; github.com/aditi-chitnis/iam-scanner</footer>
</body>
</html>"""

    with open(filename, "w") as f:
        f.write(html)
