import csv
import json
import os
from html import escape

def write_json(audit_results, path):
    """Write audit_results (a list of dicts) to a JSON file."""
    # Ensure the directory exists
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w") as f:
        json.dump(audit_results, f, indent=2)

def write_csv(audit_results, path):
    """
    Flatten audit_results into rows and write a CSV with headers:
        EntityType,EntityName,PolicyName,PolicyType,Sid,Action,Resource
    """
    os.makedirs(os.path.dirname(path), exist_ok=True)
    headers = ["EntityType", "EntityName", "PolicyName", "PolicyType", "Sid", "Action", "Resource"]
    with open(path, mode="w", newline="", encoding="utf-8") as csvfile:
        writer = csv.DictWriter(csvfile, fieldnames=headers)
        writer.writeheader()
        for entry in audit_results:
            base = {
                "EntityType": entry["EntityType"],
                "EntityName": entry["EntityName"],
                "PolicyName": entry["PolicyName"],
                "PolicyType": entry["PolicyType"]
            }
            for finding in entry["Findings"]:
                sid = finding.get("Sid", "")
                for action in finding.get("Actions", []):
                    for resource in finding.get("Resources", []):
                        row = {
                            **base,
                            "Sid": sid,
                            "Action": action,
                            "Resource": resource
                        }
                        writer.writerow(row)

def write_html(audit_results, html_path, json_path, csv_path):
    """
    Write a simple HTML report:
      - Summary section
      - Table of flagged statements
      - Links to JSON/CSV
    """
    os.makedirs(os.path.dirname(html_path), exist_ok=True)
    total_entities = len(audit_results)
    html_content = f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8" />
  <title>IAM Policy Audit Report</title>
  <style>
    body {{ font-family: Arial, sans-serif; margin: 20px; }}
    table {{ border-collapse: collapse; width: 100%; }}
    th, td {{ border: 1px solid #ddd; padding: 8px; text-align: left; }}
    th {{ background-color: #f2f2f2; }}
    tr:nth-child(even) {{ background-color: #f9f9f9; }}
  </style>
</head>
<body>
  <h1>IAM Policy Audit Report</h1>
  <p><strong>Total flagged statements:</strong> {total_entities}</p>
  <p>
    <a href="{escape(json_path)}">Download JSON</a> |
    <a href="{escape(csv_path)}">Download CSV</a>
  </p>
  <table>
    <thead>
      <tr>
        <th>EntityType</th><th>EntityName</th><th>PolicyName</th>
        <th>PolicyType</th><th>Sid</th><th>Action</th><th>Resource</th>
      </tr>
    </thead>
    <tbody>
"""
    for entry in audit_results:
        for finding in entry["Findings"]:
            sid = escape(finding.get("Sid", ""))
            for action in finding.get("Actions", []):
                for resource in finding.get("Resources", []):
                    html_content += f"""      <tr>
        <td>{escape(entry["EntityType"])}</td>
        <td>{escape(entry["EntityName"])}</td>
        <td>{escape(entry["PolicyName"])}</td>
        <td>{escape(entry["PolicyType"])}</td>
        <td>{sid}</td>
        <td>{escape(action)}</td>
        <td>{escape(resource)}</td>
      </tr>
"""
    html_content += """    </tbody>
  </table>
</body>
</html>"""
    with open(html_path, "w", encoding="utf-8") as f:
        f.write(html_content)
