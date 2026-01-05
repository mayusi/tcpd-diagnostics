"""Export utilities for diagnostics reports."""
import csv
import json
from pathlib import Path
from typing import Optional
from datetime import datetime

from ...core.result import DiagnosticsReport, Severity


def export_to_csv(report: DiagnosticsReport, filepath: str) -> bool:
    """
    Export diagnostics report to CSV format.

    Args:
        report: The diagnostics report to export
        filepath: Path to save the CSV file

    Returns:
        True if export successful, False otherwise
    """
    try:
        with open(filepath, 'w', newline='', encoding='utf-8') as f:
            writer = csv.writer(f)

            # Write header
            writer.writerow([
                'Scanner',
                'Category',
                'Severity',
                'Title',
                'Description',
                'Recommendation',
                'Component',
                'Timestamp'
            ])

            # Write findings
            for result in report.results:
                for finding in result.findings:
                    writer.writerow([
                        result.scanner_name,
                        finding.category,
                        finding.severity.value,
                        finding.title,
                        finding.description,
                        finding.recommendation or '',
                        finding.component or '',
                        result.timestamp.isoformat() if result.timestamp else ''
                    ])

        return True

    except Exception:
        return False


def export_to_html(report: DiagnosticsReport, filepath: str) -> bool:
    """
    Export diagnostics report to HTML format.

    Args:
        report: The diagnostics report to export
        filepath: Path to save the HTML file

    Returns:
        True if export successful, False otherwise
    """
    try:
        html = generate_html_report(report)
        with open(filepath, 'w', encoding='utf-8') as f:
            f.write(html)
        return True
    except Exception:
        return False


def generate_html_report(report: DiagnosticsReport) -> str:
    """Generate HTML report string."""

    # Count by severity
    critical = report.critical_count
    warnings = report.warning_count
    passed = report.pass_count

    # Generate findings rows
    findings_html = ""
    for result in report.results:
        for finding in result.findings:
            severity_class = {
                Severity.CRITICAL: "critical",
                Severity.WARNING: "warning",
                Severity.PASS: "pass",
                Severity.INFO: "info",
            }.get(finding.severity, "info")

            rec_html = f"<br><small><em>{finding.recommendation}</em></small>" if finding.recommendation else ""

            findings_html += f"""
            <tr class="{severity_class}">
                <td>{result.scanner_name}</td>
                <td><span class="badge {severity_class}">{finding.severity.value.upper()}</span></td>
                <td>{finding.title}</td>
                <td>{finding.description}{rec_html}</td>
            </tr>
            """

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>TCPD Report</title>
    <style>
        * {{ margin: 0; padding: 0; box-sizing: border-box; }}
        body {{
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Oxygen, Ubuntu, sans-serif;
            background: #1a1a2e;
            color: #eee;
            padding: 20px;
        }}
        .container {{ max-width: 1200px; margin: 0 auto; }}
        h1 {{
            text-align: center;
            padding: 20px;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            border-radius: 10px;
            margin-bottom: 20px;
        }}
        .summary {{
            display: flex;
            gap: 20px;
            margin-bottom: 20px;
        }}
        .stat {{
            flex: 1;
            padding: 20px;
            border-radius: 10px;
            text-align: center;
        }}
        .stat.critical {{ background: #e74c3c; }}
        .stat.warning {{ background: #f39c12; }}
        .stat.pass {{ background: #27ae60; }}
        .stat h2 {{ font-size: 2.5em; }}
        .stat p {{ opacity: 0.8; }}
        table {{
            width: 100%;
            border-collapse: collapse;
            background: #16213e;
            border-radius: 10px;
            overflow: hidden;
        }}
        th, td {{
            padding: 12px 15px;
            text-align: left;
            border-bottom: 1px solid #0f3460;
        }}
        th {{ background: #0f3460; }}
        tr:hover {{ background: #1a1a4e; }}
        tr.critical {{ border-left: 4px solid #e74c3c; }}
        tr.warning {{ border-left: 4px solid #f39c12; }}
        tr.pass {{ border-left: 4px solid #27ae60; }}
        tr.info {{ border-left: 4px solid #3498db; }}
        .badge {{
            padding: 3px 8px;
            border-radius: 4px;
            font-size: 0.8em;
            font-weight: bold;
        }}
        .badge.critical {{ background: #e74c3c; }}
        .badge.warning {{ background: #f39c12; color: #000; }}
        .badge.pass {{ background: #27ae60; }}
        .badge.info {{ background: #3498db; }}
        .footer {{
            text-align: center;
            padding: 20px;
            opacity: 0.6;
            margin-top: 20px;
        }}
    </style>
</head>
<body>
    <div class="container">
        <h1>TCPD System Report</h1>

        <div class="summary">
            <div class="stat critical">
                <h2>{critical}</h2>
                <p>Critical Issues</p>
            </div>
            <div class="stat warning">
                <h2>{warnings}</h2>
                <p>Warnings</p>
            </div>
            <div class="stat pass">
                <h2>{passed}</h2>
                <p>Passed Checks</p>
            </div>
        </div>

        <table>
            <thead>
                <tr>
                    <th>Scanner</th>
                    <th>Severity</th>
                    <th>Finding</th>
                    <th>Details</th>
                </tr>
            </thead>
            <tbody>
                {findings_html}
            </tbody>
        </table>

        <div class="footer">
            <p>Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
            <p>TCPD - Tester's Comprehensive PC Diagnostics</p>
        </div>
    </div>
</body>
</html>
"""
    return html


def get_default_export_path(extension: str = "json") -> str:
    """Get default export path with timestamp."""
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    return f"tcpd_{timestamp}.{extension}"
