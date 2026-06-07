# modules/report_generator.py
import json
from datetime import datetime

def generate_report(data, output_format='json'):
    """
    data: dict with keys 'target', 'status_code','server','findings',
          'attack_surface','score'.
    output_format: 'json' or 'html'. Returns string of report.
    """
    # Build structured report (dict)
    report = {
        "target": data["target"],
        "timestamp": datetime.utcnow().isoformat()+"Z",
        "status_code": data["status_code"],
        "server": data["server"],
        "findings": [
            {"id": f["id"], "title": f["title"], "risk": f["risk"], "recommendation": f["recommendation"]}
            for f in data["findings"]
        ],
        "attack_surface": data.get("attack_surface", {}),
        "score": data.get("score", None)
    }

    if output_format.lower() == 'json':
        return json.dumps(report, indent=2)

    # Simple HTML generation
    html = f"<html><head><title>Security Report for {data['target']}</title></head><body>"
    html += f"<h1>Security Assessment Report</h1>"
    html += "<h2>Summary</h2>"
    html += f"<p>Target: {data['target']}<br>Status Code: {data['status_code']}<br>"
    html += f"Server: {data['server']}</p>"
    html += "<h2>Findings</h2><table border=1><tr><th>ID</th><th>Title</th><th>Risk</th><th>Recommendation</th></tr>"
    for f in data['findings']:
        html += "<tr>"
        html += f"<td>{f['id']}</td><td>{f['title']}</td><td>{f['risk']}</td>"
        html += f"<td>{f['recommendation']}</td></tr>"
    html += "</table>"
    html += "<h2>Attack Surface</h2>"
    asf = data.get("attack_surface", {})
    html += f"<p>Forms: {asf.get('forms',0)}, Inputs: {asf.get('inputs',0)}, Links: {asf.get('links',0)}</p>"
    html += "<h2>Security Score</h2>"
    html += f"<p>{data.get('score',0)}/100</p>"
    html += "</body></html>"
    return html
