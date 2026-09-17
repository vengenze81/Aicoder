import json
import os

loot_data = []
if os.path.exists("exfil_loot.json"):
    with open("exfil_loot.json", "r") as f:
        loot_data = json.load(f)

html_content = f"""
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Red Team Engagement Report - medistore.se</title>
    <style>
        body {{ font-family: Helvetica, Arial, sans-serif; color: #1e293b; font-size: 10pt; line-height: 1.5; background-color: #f8fafc; margin: 0; padding: 20px; max-width: 800px; margin: auto; }}
        .header-banner {{ background: linear-gradient(135deg, #0f172a 0%, #1e293b 100%); color: #ffffff; padding: 24px 28px; border-radius: 6px; margin-bottom: 24px; border-left: 6px solid #b91c1c; }}
        .header-banner h1 {{ margin: 0 0 6px 0; font-size: 20pt; }}
        .subtitle {{ font-size: 10pt; color: #94a3b8; text-transform: uppercase; letter-spacing: 1px; }}
        h2 {{ color: #0f172a; font-size: 13pt; border-bottom: 2px solid #e2e8f0; padding-bottom: 6px; margin-top: 24px; margin-bottom: 12px; text-transform: uppercase; }}
        .card {{ background: #ffffff; border: 1px solid #e2e8f0; border-radius: 6px; padding: 14px 18px; margin-bottom: 14px; box-shadow: 0 1px 3px rgba(0,0,0,0.02); }}
        .card-title {{ font-weight: bold; color: #0f172a; margin-bottom: 6px; font-size: 11pt; display: flex; justify-content: space-between; }}
        .badge {{ background: #fee2e2; color: #991b1b; padding: 2px 8px; border-radius: 4px; font-size: 8pt; font-weight: bold; text-transform: uppercase; }}
        .badge-success {{ background: #dcfce7; color: #166534; }}
        table {{ width: 100%; border-collapse: collapse; margin-top: 10px; font-size: 9.5pt; }}
        th, td {{ text-align: left; padding: 8px 10px; border-bottom: 1px solid #e2e8f0; }}
        th {{ background: #f1f5f9; color: #334155; font-size: 8.5pt; text-transform: uppercase; }}
        pre {{ background: #0f172a; color: #e2e8f0; padding: 10px 12px; border-radius: 4px; font-size: 8.5pt; overflow-x: auto; }}
        .summary-stats {{ display: table; width: 100%; margin-bottom: 20px; }}
        .stat-box {{ display: table-cell; width: 25%; background: #ffffff; border: 1px solid #e2e8f0; padding: 12px; text-align: center; border-radius: 4px; }}
        .stat-box + .stat-box {{ border-left: none; }}
        .stat-number {{ font-size: 16pt; font-weight: bold; color: #b91c1c; }}
        .stat-label {{ font-size: 8pt; color: #64748b; text-transform: uppercase; }}
    </style>
</head>
<body>
    <div class="header-banner">
        <h1>Red Team Engagement Report</h1>
        <div class="subtitle">Target: https://medistore.se | Automated Operator Assessment</div>
    </div>

    <h2>Executive Summary</h2>
    <p>This report documents findings and telemetry acquired during the automated red team simulation against <strong>https://medistore.se</strong> using a custom native HTTP proxy and C2 framework.</p>

    <div class="summary-stats">
        <div class="stat-box"><div class="stat-number">{len([i for i in loot_data if i.get("action") == "form_submission"])}</div><div class="stat-label">Credentials Skimmed</div></div>
        <div class="stat-box"><div class="stat-number">{len([i for i in loot_data if "dump" in i.get("action", "")])}</div><div class="stat-label">Database Dumps</div></div>
        <div class="stat-box"><div class="stat-number">{len([i for i in loot_data if i.get("action") == "persistence_established"])}</div><div class="stat-label">Backdoors Deployed</div></div>
        <div class="stat-box"><div class="stat-number">{len(loot_data)}</div><div class="stat-label">Total Events</div></div>
    </div>

    <h2>Exfiltrated Loot & Telemetry Log</h2>
"""

for idx, entry in enumerate(loot_data, 1):
    action = entry.get("action", "unknown")
    role = entry.get("role", "N/A")
    url = entry.get("url", "N/A")
    badge_class = "badge" if role == "Administrator" else "badge badge-success"
    
    html_content += f"""
    <div class="card">
        <div class="card-title"><span>Event #{idx}: {action.upper()}</span><span class="{badge_class}">{role}</span></div>
        <p><strong>Target URL:</strong> <code>{url}</code></p>
    """
    if action == "form_submission":
        fields = entry.get("capturedFields", {})
        html_content += "<table><tr><th>Field Name</th><th>Captured Value</th></tr>"
        for k, v in fields.items():
            html_content += f"<tr><td><code>{k}</code></td><td><strong>{v}</strong></td></tr>"
        html_content += "</table>"
    elif "dump" in action:
        records = entry.get("data", [])
        html_content += f"<p><strong>Records Acquired:</strong> {len(records)} entries</p>"
        if records:
            html_content += "<pre>" + json.dumps(records[0], indent=2) + "</pre>"
    elif action == "persistence_established":
        acc = entry.get("accountDetails", {})
        html_content += f"<p><strong>Backdoor Account:</strong> ID {acc.get('id')} ({acc.get('username')})</p>"
    html_content += "</div>"

html_content += "</body></html>"

with open("medistore_red_team_engagement_report.html", "w") as f:
    f.write(html_content)

print("[+] Successfully generated medistore_red_team_engagement_report.html")
