# AWS IAM Policy Auditor – Enhanced

A Python-based command-line tool to scan AWS IAM users, groups, and roles for overly broad permissions (e.g., `"Action": "*"` or `"Resource": "*"`) and produce JSON, CSV, and HTML reports. If any risky policies are detected, an alert is sent via AWS SNS. This enhanced version includes customizable notifications, richer output formats, unit tests, HTML reporting, and continuous integration configuration.

---

## Table of Contents

1. [What’s New & “Twist” Feature](#whats-new--twist-feature)  
2. [What You’ll Learn & Key Takeaways](#what-youll-learn--key-takeaways)  
3. [Prerequisites](#prerequisites)  
   1. [AWS Free Tier Account Setup](#aws-free-tier-account-setup)  
   2. [IAM Permissions & Free Tier Considerations](#iam-permissions--free-tier-considerations)  
   3. [Local Machine Setup (Python, Git, VS Code)](#local-machine-setup-python-git-vs-code)  
4. [Project Structure (Ultra-Detailed)](#project-structure-ultra-detailed)  
5. [Step-by-Step Setup & Installation](#step-by-step-setup--installation)  
   1. [Clone/Create the Project Folder](#1-clonecreate-the-project-folder)  
   2. [Create & Track the `audits/` Directory](#2-create--track-the-audits-directory)  
   3. [Create & Activate Python Virtual Environment](#3-create--activate-python-virtual-environment)  
   4. [Install Python Dependencies](#4-install-python-dependencies)  
   5. [Configure AWS CLI with Your Free Tier Credentials](#5-configure-aws-cli-with-your-free-tier-credentials)  
   6. [Create SNS Topic & Email Subscription](#6-create-sns-topic--email-subscription)  
   7. [Configure `src/main.py` Constants](#7-configure-srcmainpy-constants)  
   8. [Run Unit Tests to Verify Setup](#8-run-unit-tests-to-verify-setup)  
6. [Code Walkthrough & Customizations](#code-walkthrough--customizations)  
   1. [`src/main.py` – Core Auditor Logic](#a-srcmainpy--core-auditor-logic)  
   2. [`src/sns_notifier.py` – SNS Publishing](#b-srcsns_notifypy--sns-publishing)  
   3. [`src/reporters.py` – JSON, CSV & HTML Reports](#c-srcreporterspy--json-csv--html-reports)  
   4. [`tests/test_auditor.py` – Unit Tests with `pytest` & `moto`](#d-teststest_auditorpy--unit-tests-with-pytest--moto)  
7. [Usage Examples & Sample Outputs](#usage-examples--sample-outputs)  
   1. [Running the Auditor](#running-the-auditor)  
   2. [Inspecting Reports (JSON, CSV, HTML)](#inspecting-reports-json-csv-html)  
   3. [SNS Email Alert](#sns-email-alert)  
8. [Troubleshooting & Common Pitfalls](#troubleshooting--common-pitfalls)  
9. [Extra-Mile Modifications & Further Ideas](#extra-mile-modifications--further-ideas)  
10. [License (MIT)](#license-mit)  
11. [Uploading to GitHub](#uploading-to-github)

---

## What’s New & “Twist” Feature

- **SNS Alerting**  
  - If any overly broad policy statements are detected, a message is published to a preconfigured AWS SNS topic, sending an email (or SMS) alert immediately.  
  - SNS publishes are free up to 1 million per month (Free Tier).  

- **CSV Output & HTML Report**  
  - In addition to JSON, results are output as a CSV (for easy spreadsheet analysis).  
  - A standalone HTML report is generated with a summary table and links to raw JSON/CSV, so stakeholders can review in a browser.  

- **Unit Tests & CI Configuration**  
  - Basic unit tests (using `pytest` and the `moto` library) verify the policy-scanning logic without real AWS calls.  
  - A GitHub Actions workflow (`.github/workflows/ci.yml`) runs tests automatically on each push or pull request.  

- **README Highlights**  
  - Clearly marks which files represent the “extra-mile” (e.g., `src/sns_notifier.py`, `src/reporters.py`, `tests/…`).  
  - Explains challenges encountered (serializing AWS policy JSON, handling pagination, configuring SNS permissions).  
  - Includes placeholders for screenshots (console output, sample HTML report, SNS email).

---

## What You’ll Learn & Key Takeaways

- **Boto3 & Pagination**  
  - Use IAM paginators (`list_users`, `list_groups`, `list_roles`, `list_*_policies`) to enumerate thousands of entities without hitting API limits.  
  - Retrieve both inline and managed policies for users, groups, and roles.  

- **Policy Document Parsing**  
  - Normalize single-statement (dict) vs. multi-statement (list) policies.  
  - Detect wildcard usage (`"Action": "*"`, `"Resource": "*"`) with care.  

- **AWS SNS Integration**  
  - Create/configure an SNS topic and grant `sns:Publish` to your IAM user.  
  - Publish structured alerts so subscribers receive a concise email.  

- **Report Generation**  
  - Use Python’s `csv` module for well-formatted CSV output.  
  - Use simple string templating (and `html.escape`) to generate a minimal HTML report.  

- **Unit Testing Boto3 Code**  
  - Mock AWS IAM/SNS calls with the `moto` library so tests run offline.  
  - Verify that `check_policy_for_overly_broad()` correctly flags wildcards.  

- **Continuous Integration (CI)**  
  - GitHub Actions workflow automatically runs tests on Python 3.9 and 3.10 for each push.  

- **Best Practices in Python Project Structure**  
  - Separate core logic (`src/`) from tests (`tests/`).  
  - Centralize configuration (SNS topic ARN, output paths) in `main.py`.  
  - Write clear docstrings and comments.

---

## Prerequisites

### AWS Free Tier Account Setup

1. **Sign Up for AWS Free Tier**  
   - Visit [aws.amazon.com/free](https://aws.amazon.com/free/) and create a Free Tier account.  
   - Provide contact information, a valid credit card (for verification), and verify your phone.  
   - Choose the **Basic Support (Free)** plan.  

2. **Create an IAM User (`auditor-user`)**  
   - Log in as the **root user** to the AWS Console.  
   - Go to **IAM → Users → Add users**.  
     - **User name**: `auditor-user`  
     - **Access type**: Check **Programmatic access**  
   - Skip attaching AWS-managed policies; we will attach a custom inline policy next.  
   - Finish user creation and note the **Access Key ID** and **Secret Access Key** (or download the `.csv`).  

3. **Attach a Custom Inline Policy to `auditor-user`**  
   - Go to **IAM → Users → auditor-user → Permissions → Add inline policy**.  
   - Choose the **JSON** tab, paste:
     ```json
     {
       "Version": "2012-10-17",
       "Statement": [
         {
           "Effect": "Allow",
           "Action": [
             "iam:ListUsers",
             "iam:ListGroups",
             "iam:ListRoles",
             "iam:GetUserPolicy",
             "iam:ListAttachedUserPolicies",
             "iam:GetGroupPolicy",
             "iam:ListAttachedGroupPolicies",
             "iam:GetRolePolicy",
             "iam:ListAttachedRolePolicies",
             "sns:Publish"
           ],
           "Resource": "*"
         }
       ]
     }
     ```
   - Name it `AuditorMinimalPermissions` and click **Create policy**.

> **Free Tier Note (IAM & SNS):**  
> - IAM read‐only calls (ListUsers, ListGroups, etc.) are free.  
> - SNS is free up to 1 million publishes and 100 000 email deliveries per month.  

---

### Local Machine Setup (Python, Git, VS Code)

1. **Operating System**  
   - You can use Windows 10/11 (64-bit), macOS, or Linux. Steps assume Windows; adjust for macOS/Linux (`python3` instead of `python`, `source venv/bin/activate` instead of `venv\Scripts\activate`).  

2. **Install Git**  
   - Download/install from [git-scm.com](https://git-scm.com/downloads).  
   - After installation, open a terminal and run:
     ```bash
     git --version
     ```
     You should see a version string like `git version 2.x.x`.  

3. **Install Python 3.9+**  
   - Download from [python.org](https://www.python.org/downloads/windows/) (Windows) or use your package manager (macOS/Linux).  
   - **Important**: Check “Add Python to PATH” during installation.  
   - Verify:
     ```bash
     python --version
     ```
     Expect `Python 3.10.x` or higher.  

4. **Install VS Code (or any code editor)**  
   - Download from [code.visualstudio.com](https://code.visualstudio.com/).  
   - Install the **Python extension** (Microsoft) for IntelliSense, linting, and debugging.  

5. **Install AWS CLI v2**  
   - Download from [aws.amazon.com/cli](https://aws.amazon.com/cli/) (Windows MSI).  
   - Install, then verify:
     ```bash
     aws --version
     ```
     You should see `aws-cli/2.x.x Python/3.x.x`.  

6. **Configure AWS CLI**  
   - Run:
     ```bash
     aws configure
     ```
     - **AWS Access Key ID**: paste `auditor-user` Access Key  
     - **AWS Secret Access Key**: paste Secret Access Key  
     - **Default region name**: e.g., `us-east-1`  
     - **Default output format**: `json`  
   - Verify:
     ```bash
     aws sts get-caller-identity
     ```
     Expect a JSON response with your IAM User ARN.  

7. **Install Python Virtual Environment Tools**  
   - Windows: `python -m pip install --upgrade pip virtualenv`  
   - macOS/Linux: `python3 -m pip install --upgrade pip virtualenv`  

---

## Project Structure (Ultra-Detailed)

aws-iam-policy-auditor/
├── audits/ # Output folder (contains .gitkeep)
│ └── .gitkeep
├── src/ # Core Python package
│ ├── init.py
│ ├── main.py # Entry point for auditing + SNS
│ ├── sns_notifier.py # Logic to publish to AWS SNS
│ └── reporters.py # JSON, CSV & HTML report generation
├── tests/ # Unit tests (moto + pytest)
│ ├── init.py
│ └── test_auditor.py
├── .github/ # CI/CD configuration (GitHub Actions)
│ └── workflows/
│ └── ci.yml # Runs pytest on each push/PR
├── .gitignore
├── requirements.txt # Python dependencies (pinned)
├── LICENSE # MIT License
└── README.md # This file


- **`audits/`**  
  - Holds output files (`.json`, `.csv`, `.html`). `.gitkeep` ensures the folder is tracked even when empty.  

- **`src/`**  
  - `__init__.py`: Marks `src` as a Python package (can be empty).  
  - `main.py`: Orchestrates scanning IAM entities, detecting wildcards, writing reports, and sending SNS alerts.  
  - `sns_notifier.py`: Encapsulates SNS publishing (`publish_to_sns(...)`).  
  - `reporters.py`: Contains `write_json`, `write_csv`, and `write_html` functions for reporting.  

- **`tests/`**  
  - Contains `pytest` unit tests. We use the `moto` library to mock IAM calls, avoiding real AWS usage.  

- **`.github/workflows/ci.yml`**  
  - GitHub Actions workflow: checks out code, sets up Python 3.9 & 3.10, installs dependencies, runs `pytest`.  

- **`requirements.txt`**  
  ```txt
  boto3==1.28.0
  tabulate==0.9.0
  jinja2==3.1.2
  pytest==7.4.0
  moto==4.0.5

    LICENSE

        MIT License text.

    README.md

        This detailed guide.

Step-by-Step Setup & Installation

    Beginner Tip: Whenever you see a command prefixed with >, type it exactly (without the >). On macOS/Linux, replace python with python3 and use source venv/bin/activate instead of venv\Scripts\activate.

1. Clone/Create the Project Folder

    Open Command Prompt (Windows) or Terminal (macOS/Linux).

    Navigate to your Projects directory (e.g., C:\Users\<YourName>\Projects):

> cd C:\Users\<YourName>\Projects

Create a new folder and enter it:

    > mkdir aws-iam-policy-auditor
    > cd aws-iam-policy-auditor

2. Create & Track the audits/ Directory

    Create the audits folder:

> mkdir audits

Inside audits/, create a .gitkeep file so Git will track the empty folder:

> echo "# Keep this folder for audit outputs" > audits\.gitkeep

Initialize Git (if not already done):

> git init

Create a .gitignore file in the project root with the following content:

venv/
*.pem
*.key
.DS_Store
__pycache__/
*.pyc
.vscode/
.pytest_cache/
*.log

Commit initial structure:

    > git add .
    > git commit -m "Initial commit: add audits folder and .gitignore"

3. Create & Activate Python Virtual Environment

    Create a virtual environment named venv:

> python -m venv venv

Activate it:

    Windows (Command Prompt):

> venv\Scripts\activate

macOS/Linux:

    $ source venv/bin/activate

Verify activation ((venv) should appear in your prompt) and Python version:

(venv) > python --version

Expect Python 3.10.x or higher.

Upgrade pip inside the venv:

    (venv) > python -m pip install --upgrade pip

4. Install Python Dependencies

    Create requirements.txt in the project root with:

boto3==1.28.0
tabulate==0.9.0
jinja2==3.1.2
pytest==7.4.0
moto==4.0.5

Install all dependencies:

(venv) > pip install -r requirements.txt

(Optional) Freeze versions after installation:

    (venv) > pip freeze > requirements.txt

5. Configure AWS CLI with Your Free Tier Credentials

    In your terminal (with venv activated), run:

(venv) > aws configure

    AWS Access Key ID: paste the Access Key from auditor-user.

    AWS Secret Access Key: paste the Secret Key.

    Default region name: e.g., us-east-1.

    Default output format: json.

Verify with:

    (venv) > aws sts get-caller-identity

    Expect a JSON response with your IAM user ARN.

6. Create SNS Topic & Email Subscription

    In the AWS Console, navigate to SNS → Topics → Create topic.

        Type: Standard

        Name: iam-audit-alerts

        Click Create topic.

    Copy the Topic ARN (e.g., arn:aws:sns:us-east-1:123456789012:iam-audit-alerts).

    In SNS, go to Subscriptions → Create subscription.

        Topic ARN: prefilled

        Protocol: Email

        Endpoint: your personal email

        Click Create subscription.

    Check your email; click the “Confirm subscription” link in the SNS confirmation email.

    Free Tier Note: SNS is free up to 1 million publishes and 100 000 email deliveries per month.

7. Configure src/main.py Constants

    Create the src/ folder:

(venv) > mkdir src

Inside src/, create:

    __init__.py (empty)

    main.py

    sns_notifier.py

    reporters.py

Open src/main.py and paste:

import boto3
import json
import csv
import os
from botocore.exceptions import ClientError

from sns_notifier import publish_to_sns
from reporters import write_csv, write_json, write_html

# ------------------------------
# Configuration Section
# ------------------------------
OUTPUT_JSON = "audits/iam_policy_audit_report.json"
OUTPUT_CSV  = "audits/iam_policy_audit_report.csv"
OUTPUT_HTML = "audits/iam_policy_audit_report.html"

SNS_TOPIC_ARN = "arn:aws:sns:us-east-1:123456789012:iam-audit-alerts"
# ------------------------------

    Replace the SNS ARN with your actual ARN from Step 6.

    Save the file.

In src/sns_notifier.py, paste:

import boto3
from botocore.exceptions import ClientError

def publish_to_sns(topic_arn: str, subject: str, message: str) -> None:
    """
    Publish a message to the given SNS topic.
    Raises ClientError on failure.
    """
    sns = boto3.client("sns")
    try:
        response = sns.publish(
            TopicArn=topic_arn,
            Subject=subject,
            Message=message
        )
    except ClientError as e:
        raise

In src/reporters.py, paste:

import csv
import json
import os
from html import escape

def write_json(audit_results, path):
    """Write audit_results (a list of dicts) to a JSON file."""
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

In src/main.py, paste the core auditor logic below the configuration section:

    def get_iam_client():
        """Return a boto3 IAM client using default credentials/profile."""
        return boto3.client("iam")

    def list_all_entities(iam):
        """Retrieve all IAM users, groups, and roles in the account."""
        users, groups, roles = [], [], []

        # Paginate through list_users
        paginator = iam.get_paginator("list_users")
        for page in paginator.paginate():
            users.extend(page["Users"])

        # Paginate through list_groups
        paginator = iam.get_paginator("list_groups")
        for page in paginator.paginate():
            groups.extend(page["Groups"])

        # Paginate through list_roles
        paginator = iam.get_paginator("list_roles")
        for page in paginator.paginate():
            roles.extend(page["Roles"])

        return users, groups, roles

    def get_policies_for_user(iam, user_name):
        """Return inline and attached managed policies for a given user."""
        inline, attached = [], []
        # Inline policies
        paginator = iam.get_paginator("list_user_policies")
        for page in paginator.paginate(UserName=user_name):
            inline.extend(page["PolicyNames"])
        for policy_name in inline:
            doc = iam.get_user_policy(UserName=user_name, PolicyName=policy_name)["PolicyDocument"]
            yield policy_name, doc, "UserInline", user_name

        # Attached managed policies
        paginator = iam.get_paginator("list_attached_user_policies")
        for page in paginator.paginate(UserName=user_name):
            attached.extend(page["AttachedPolicies"])
        for pol in attached:
            pol_arn = pol["PolicyArn"]
            version = iam.get_policy(PolicyArn=pol_arn)["Policy"]["DefaultVersionId"]
            doc = iam.get_policy_version(PolicyArn=pol_arn, VersionId=version)["PolicyVersion"]["Document"]
            yield pol["PolicyName"], doc, "UserManaged", user_name

    def get_policies_for_group(iam, group_name):
        """Return inline and attached managed policies for a given group."""
        inline, attached = [], []
        # Inline policies
        paginator = iam.get_paginator("list_group_policies")
        for page in paginator.paginate(GroupName=group_name):
            inline.extend(page["PolicyNames"])
        for policy_name in inline:
            doc = iam.get_group_policy(GroupName=group_name, PolicyName=policy_name)["PolicyDocument"]
            yield policy_name, doc, "GroupInline", group_name

        # Attached managed policies
        paginator = iam.get_paginator("list_attached_group_policies")
        for page in paginator.paginate(GroupName=group_name):
            attached.extend(page["AttachedPolicies"])
        for pol in attached:
            pol_arn = pol["PolicyArn"]
            version = iam.get_policy(PolicyArn=pol_arn)["Policy"]["DefaultVersionId"]
            doc = iam.get_policy_version(PolicyArn=pol_arn, VersionId=version)["PolicyVersion"]["Document"]
            yield pol["PolicyName"], doc, "GroupManaged", group_name

    def get_policies_for_role(iam, role_name):
        """Return inline and attached managed policies for a given role."""
        inline, attached = [], []
        # Inline policies
        paginator = iam.get_paginator("list_role_policies")
        for page in paginator.paginate(RoleName=role_name):
            inline.extend(page["PolicyNames"])
        for policy_name in inline:
            doc = iam.get_role_policy(RoleName=role_name, PolicyName=policy_name)["PolicyDocument"]
            yield policy_name, doc, "RoleInline", role_name

        # Attached managed policies
        paginator = iam.get_paginator("list_attached_role_policies")
        for page in paginator.paginate(RoleName=role_name):
            attached.extend(page["AttachedPolicies"])
        for pol in attached:
            pol_arn = pol["PolicyArn"]
            version = iam.get_policy(PolicyArn=pol_arn)["Policy"]["DefaultVersionId"]
            doc = iam.get_policy_version(PolicyArn=pol_arn, VersionId=version)["PolicyVersion"]["Document"]
            yield pol["PolicyName"], doc, "RoleManaged", role_name

    def check_policy_for_overly_broad(doc):
        """
        Returns a list of findings if the policy document has any statements with
        Effect=Allow, Action='*', Resource='*'.
        """
        findings = []
        statements = doc.get("Statement", [])
        if not isinstance(statements, list):
            statements = [statements]

        for stmt in statements:
            if stmt.get("Effect", "") == "Allow":
                actions = stmt.get("Action", [])
                resources = stmt.get("Resource", [])
                if isinstance(actions, str):
                    actions = [actions]
                if isinstance(resources, str):
                    resources = [resources]

                if "*" in actions or "*" in resources:
                    findings.append({
                        "Sid": stmt.get("Sid", ""),
                        "Actions": actions,
                        "Resources": resources
                    })
        return findings

    def main():
        iam = get_iam_client()
        users, groups, roles = list_all_entities(iam)
        audit_results = []

        # Audit Users
        for user in users:
            user_name = user["UserName"]
            for pol_name, doc, pol_type, principal in get_policies_for_user(iam, user_name):
                findings = check_policy_for_overly_broad(doc)
                if findings:
                    audit_results.append({
                        "EntityType": "User",
                        "EntityName": principal,
                        "PolicyName": pol_name,
                        "PolicyType": pol_type,
                        "Findings": findings
                    })

        # Audit Groups
        for grp in groups:
            group_name = grp["GroupName"]
            for pol_name, doc, pol_type, principal in get_policies_for_group(iam, group_name):
                findings = check_policy_for_overly_broad(doc)
                if findings:
                    audit_results.append({
                        "EntityType": "Group",
                        "EntityName": principal,
                        "PolicyName": pol_name,
                        "PolicyType": pol_type,
                        "Findings": findings
                    })

        # Audit Roles
        for rl in roles:
            role_name = rl["RoleName"]
            for pol_name, doc, pol_type, principal in get_policies_for_role(iam, role_name):
                findings = check_policy_for_overly_broad(doc)
                if findings:
                    audit_results.append({
                        "EntityType": "Role",
                        "EntityName": principal,
                        "PolicyName": pol_name,
                        "PolicyType": pol_type,
                        "Findings": findings
                    })

        # Ensure audits folder exists
        os.makedirs(os.path.dirname(OUTPUT_JSON), exist_ok=True)

        # Write outputs
        write_json(audit_results, OUTPUT_JSON)
        write_csv(audit_results, OUTPUT_CSV)
        write_html(audit_results, OUTPUT_HTML, OUTPUT_JSON, OUTPUT_CSV)

        print(f"Audit complete. JSON: {OUTPUT_JSON}, CSV: {OUTPUT_CSV}, HTML: {OUTPUT_HTML}")

        # If there are any findings, send an SNS alert
        if audit_results:
            subject = "⚠️ IAM Policy Auditor: Overly Broad Permissions Detected"
            message = (
                f"IAM Policy Auditor has detected {len(audit_results)} "
                f"entities with overly broad permissions.\n\n"
                f"JSON Report: {OUTPUT_JSON}\n"
                f"CSV Report: {OUTPUT_CSV}\n"
                f"HTML Report: {OUTPUT_HTML}"
            )
            try:
                publish_to_sns(SNS_TOPIC_ARN, subject, message)
                print("SNS alert sent.")
            except ClientError as e:
                print(f"Failed to send SNS alert: {e}")

    if __name__ == "__main__":
        main()

8. Run Unit Tests to Verify Setup

    Create the tests/ folder:

(venv) > mkdir tests

Inside tests/, create:

    __init__.py (empty)

    test_auditor.py

In tests/test_auditor.py, paste:

import pytest
from src.main import check_policy_for_overly_broad

@pytest.fixture
def policy_single_wildcard():
    return {
        "Version": "2012-10-17",
        "Statement": {
            "Sid": "Stmt1",
            "Effect": "Allow",
            "Action": "*",
            "Resource": "*"
        }
    }

@pytest.fixture
def policy_no_wildcard():
    return {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": "StmtSafe",
                "Effect": "Allow",
                "Action": ["iam:ListUsers"],
                "Resource": ["arn:aws:iam::123456789012:user/*"]
            },
            {
                "Sid": "StmtSpecific",
                "Effect": "Allow",
                "Action": ["ec2:StartInstances"],
                "Resource": ["arn:aws:ec2:us-east-1:123456789012:instance/*"]
            }
        ]
    }

def test_wildcard_detected(policy_single_wildcard):
    findings = check_policy_for_overly_broad(policy_single_wildcard)
    assert isinstance(findings, list)
    assert len(findings) == 1
    assert findings[0]["Actions"] == ["*"]
    assert findings[0]["Resources"] == ["*"]

def test_no_wildcard(policy_no_wildcard):
    findings = check_policy_for_overly_broad(policy_no_wildcard)
    assert findings == []

Ensure PYTHONPATH includes src/ so tests can import:

    Windows (Command Prompt):

(venv) > set PYTHONPATH=%cd%\src
(venv) > pytest --maxfail=1 --disable-warnings -q

macOS/Linux (bash):

    (venv) $ export PYTHONPATH=$(pwd)/src
    (venv) $ pytest --maxfail=1 --disable-warnings -q

You should see:

    ====== test session starts ======
    collected 2 items

    tests/test_auditor.py ..
    ====== 2 passed in 0.27s ======

    If tests fail, revisit your check_policy_for_overly_broad() implementation.

Code Walkthrough & Customizations
a. src/main.py – Core Auditor Logic

    Imports & Configuration

import boto3
import json
import csv
import os
from botocore.exceptions import ClientError

from sns_notifier import publish_to_sns
from reporters import write_csv, write_json, write_html

# ------------------------------
# Configuration Section
# ------------------------------
OUTPUT_JSON = "audits/iam_policy_audit_report.json"
OUTPUT_CSV  = "audits/iam_policy_audit_report.csv"
OUTPUT_HTML = "audits/iam_policy_audit_report.html"

SNS_TOPIC_ARN = "arn:aws:sns:us-east-1:123456789012:iam-audit-alerts"
# ------------------------------

    Defines output file paths and SNS topic ARN at the top for easy modification.

IAM Client & Entity Listing

def get_iam_client():
    return boto3.client("iam")

def list_all_entities(iam):
    users, groups, roles = [], [], []

    # Paginate through list_users
    paginator = iam.get_paginator("list_users")
    for page in paginator.paginate():
        users.extend(page["Users"])

    # Paginate through list_groups
    paginator = iam.get_paginator("list_groups")
    for page in paginator.paginate():
        groups.extend(page["Groups"])

    # Paginate through list_roles
    paginator = iam.get_paginator("list_roles")
    for page in paginator.paginate():
        roles.extend(page["Roles"])

    return users, groups, roles

    Uses boto3 paginators to retrieve all IAM users, groups, and roles—even if there are thousands.

    Free Tier covers IAM read API calls.

Retrieving Policies
Each of the following functions yields (policy_name, policy_document, policy_type, principal_name) for a given entity type:

def get_policies_for_user(iam, user_name):
    inline, attached = [], []

    # Inline policies
    paginator = iam.get_paginator("list_user_policies")
    for page in paginator.paginate(UserName=user_name):
        inline.extend(page["PolicyNames"])
    for policy_name in inline:
        doc = iam.get_user_policy(UserName=user_name, PolicyName=policy_name)["PolicyDocument"]
        yield policy_name, doc, "UserInline", user_name

    # Attached managed policies
    paginator = iam.get_paginator("list_attached_user_policies")
    for page in paginator.paginate(UserName=user_name):
        attached.extend(page["AttachedPolicies"])
    for pol in attached:
        pol_arn = pol["PolicyArn"]
        version = iam.get_policy(PolicyArn=pol_arn)["Policy"]["DefaultVersionId"]
        doc = iam.get_policy_version(PolicyArn=pol_arn, VersionId=version)["PolicyVersion"]["Document"]
        yield pol["PolicyName"], doc, "UserManaged", user_name

def get_policies_for_group(iam, group_name):
    inline, attached = [], []

    # Inline policies
    paginator = iam.get_paginator("list_group_policies")
    for page in paginator.paginate(GroupName=group_name):
        inline.extend(page["PolicyNames"])
    for policy_name in inline:
        doc = iam.get_group_policy(GroupName=group_name, PolicyName=policy_name)["PolicyDocument"]
        yield policy_name, doc, "GroupInline", group_name

    # Attached managed policies
    paginator = iam.get_paginator("list_attached_group_policies")
    for page in paginator.paginate(GroupName=group_name):
        attached.extend(page["AttachedPolicies"])
    for pol in attached:
        pol_arn = pol["PolicyArn"]
        version = iam.get_policy(PolicyArn=pol_arn)["Policy"]["DefaultVersionId"]
        doc = iam.get_policy_version(PolicyArn=pol_arn, VersionId=version)["PolicyVersion"]["Document"]
        yield pol["PolicyName"], doc, "GroupManaged", group_name

def get_policies_for_role(iam, role_name):
    inline, attached = [], []

    # Inline policies
    paginator = iam.get_paginator("list_role_policies")
    for page in paginator.paginate(RoleName=role_name):
        inline.extend(page["PolicyNames"])
    for policy_name in inline:
        doc = iam.get_role_policy(RoleName=role_name, PolicyName=policy_name)["PolicyDocument"]
        yield policy_name, doc, "RoleInline", role_name

    # Attached managed policies
    paginator = iam.get_paginator("list_attached_role_policies")
    for page in paginator.paginate(RoleName=role_name):
        attached.extend(page["AttachedPolicies"])
    for pol in attached:
        pol_arn = pol["PolicyArn"]
        version = iam.get_policy(PolicyArn=pol_arn)["Policy"]["DefaultVersionId"]
        doc = iam.get_policy_version(PolicyArn=pol_arn, VersionId=version)["PolicyVersion"]["Document"]
        yield pol["PolicyName"], doc, "RoleManaged", role_name

    Each inline-policy call (get_user_policy, get_group_policy, get_role_policy) retrieves the policy document directly.

    For attached managed policies, we call get_policy to find the default version, then get_policy_version to retrieve the document.

    All of these calls are covered by IAM Free Tier.

Policy Scanning Logic

def check_policy_for_overly_broad(doc):
    """
    Returns a list of findings if the policy document has any statements with
    Effect=Allow, Action='*', Resource='*'.
    """
    findings = []
    statements = doc.get("Statement", [])
    if not isinstance(statements, list):
        statements = [statements]

    for stmt in statements:
        if stmt.get("Effect", "") == "Allow":
            actions = stmt.get("Action", [])
            resources = stmt.get("Resource", [])
            if isinstance(actions, str):
                actions = [actions]
            if isinstance(resources, str):
                resources = [resources]

            if "*" in actions or "*" in resources:
                findings.append({
                    "Sid": stmt.get("Sid", ""),
                    "Actions": actions,
                    "Resources": resources
                })
    return findings

    Normalizes single-statement dictionaries into a list so all code paths treat Statement uniformly.

    Checks if "Effect": "Allow" and either "Action" or "Resource" contains "*".

    Returns a list of findings—each finding includes "Sid", "Actions", and "Resources" that triggered the rule.

Main Function

    def main():
        iam = get_iam_client()
        users, groups, roles = list_all_entities(iam)
        audit_results = []

        # Audit Users
        for user in users:
            user_name = user["UserName"]
            for pol_name, doc, pol_type, principal in get_policies_for_user(iam, user_name):
                findings = check_policy_for_overly_broad(doc)
                if findings:
                    audit_results.append({
                        "EntityType": "User",
                        "EntityName": principal,
                        "PolicyName": pol_name,
                        "PolicyType": pol_type,
                        "Findings": findings
                    })

        # Audit Groups
        for grp in groups:
            group_name = grp["GroupName"]
            for pol_name, doc, pol_type, principal in get_policies_for_group(iam, group_name):
                findings = check_policy_for_overly_broad(doc)
                if findings:
                    audit_results.append({
                        "EntityType": "Group",
                        "EntityName": principal,
                        "PolicyName": pol_name,
                        "PolicyType": pol_type,
                        "Findings": findings
                    })

        # Audit Roles
        for rl in roles:
            role_name = rl["RoleName"]
            for pol_name, doc, pol_type, principal in get_policies_for_role(iam, role_name):
                findings = check_policy_for_overly_broad(doc)
                if findings:
                    audit_results.append({
                        "EntityType": "Role",
                        "EntityName": principal,
                        "PolicyName": pol_name,
                        "PolicyType": pol_type,
                        "Findings": findings
                    })

        # Ensure audits folder exists
        os.makedirs(os.path.dirname(OUTPUT_JSON), exist_ok=True)

        # Write outputs
        write_json(audit_results, OUTPUT_JSON)
        write_csv(audit_results, OUTPUT_CSV)
        write_html(audit_results, OUTPUT_HTML, OUTPUT_JSON, OUTPUT_CSV)

        print(f"Audit complete. JSON: {OUTPUT_JSON}, CSV: {OUTPUT_CSV}, HTML: {OUTPUT_HTML}")

        # If there are any findings, send an SNS alert
        if audit_results:
            subject = "⚠️ IAM Policy Auditor: Overly Broad Permissions Detected"
            message = (
                f"IAM Policy Auditor has detected {len(audit_results)} "
                f"entities with overly broad permissions.\n\n"
                f"JSON Report: {OUTPUT_JSON}\n"
                f"CSV Report: {OUTPUT_CSV}\n"
                f"HTML Report: {OUTPUT_HTML}"
            )
            try:
                publish_to_sns(SNS_TOPIC_ARN, subject, message)
                print("SNS alert sent.")
            except ClientError as e:
                print(f"Failed to send SNS alert: {e}")

    if __name__ == "__main__":
        main()

        Gathers all IAM entities, retrieves their policies, scans each policy, and accumulates any findings into audit_results.

        Ensures the audits/ directory exists, then calls write_json, write_csv, and write_html.

        Prints a summary message and, if any findings exist, publishes an SNS alert with the report file paths.

        SNS publishing uses the publish_to_sns() function in sns_notifier.py.

b. src/sns_notifier.py – SNS Publishing

import boto3
from botocore.exceptions import ClientError

def publish_to_sns(topic_arn: str, subject: str, message: str) -> None:
    """
    Publish a message to the given SNS topic.
    Raises ClientError on failure.
    """
    sns = boto3.client("sns")
    try:
        response = sns.publish(
            TopicArn=topic_arn,
            Subject=subject,
            Message=message
        )
        # Optionally, log response["MessageId"]
    except ClientError as e:
        # Bubble up the exception so main() can catch it
        raise

    Instantiates an SNS client using your default credentials/profile.

    Calls publish(...) with the topic ARN, subject, and body message.

    If SNS publish fails (invalid ARN or missing permission), catches ClientError and re-raises it so main.py can print an error message.

    Free Tier Note: SNS publish calls are free up to 1 million/month. An occasional alert will not incur any charges.

c. src/reporters.py – JSON, CSV & HTML Reports

import csv
import json
import os
from html import escape

def write_json(audit_results, path):
    """Write audit_results (a list of dicts) to a JSON file."""
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

    write_json: Dumps audit_results (a Python list of dicts) to a JSON file with indentation.

    write_csv: Flattens each finding so that each combination of "Action" and "Resource" becomes its own row. Includes headers for easy spreadsheet import.

    write_html: Builds a minimal HTML page with inline CSS. Displays the total number of flagged statements, links to download JSON/CSV, and a <table> of all flagged statements. Uses html.escape to prevent HTML injection if policy names contain special characters.

    Free Tier Note: All these reporters run locally and do not touch AWS.

d. tests/test_auditor.py – Unit Tests with pytest & moto

import pytest
from src.main import check_policy_for_overly_broad

@pytest.fixture
def policy_single_wildcard():
    # Single statement as dict, wildcard action & resource
    return {
        "Version": "2012-10-17",
        "Statement": {
            "Sid": "Stmt1",
            "Effect": "Allow",
            "Action": "*",
            "Resource": "*"
        }
    }

@pytest.fixture
def policy_no_wildcard():
    # List of statements, one safe, one with specific action/resource
    return {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": "StmtSafe",
                "Effect": "Allow",
                "Action": ["iam:ListUsers"],
                "Resource": ["arn:aws:iam::123456789012:user/*"]
            },
            {
                "Sid": "StmtSpecific",
                "Effect": "Allow",
                "Action": ["ec2:StartInstances"],
                "Resource": ["arn:aws:ec2:us-east-1:123456789012:instance/*"]
            }
        ]
    }

def test_wildcard_detected(policy_single_wildcard):
    findings = check_policy_for_overly_broad(policy_single_wildcard)
    assert isinstance(findings, list)
    assert len(findings) == 1
    assert findings[0]["Actions"] == ["*"]
    assert findings[0]["Resources"] == ["*"]

def test_no_wildcard(policy_no_wildcard):
    findings = check_policy_for_overly_broad(policy_no_wildcard)
    assert findings == []

    Two fixtures define sample policy documents: one with a wildcard and one without.

    test_wildcard_detected ensures a wildcard policy returns exactly one finding with "*".

    test_no_wildcard ensures no findings for safe policies.

    No real AWS calls—this tests only the Python function, so you’re not charged or consuming Free Tier.

Usage Examples & Sample Outputs
Running the Auditor

    Activate your virtual environment (if not already active):

> cd C:\Users\<YourName>\Projects\aws-iam-policy-auditor
> venv\Scripts\activate

Run:

(venv) > python src\main.py

Expected Output:

    Audit complete. JSON: audits/iam_policy_audit_report.json, CSV: audits/iam_policy_audit_report.csv, HTML: audits/iam_policy_audit_report.html
    SNS alert sent.

        If there are no flagged policies, you will see the first line only (no “SNS alert sent.”).

Inspecting Reports (JSON, CSV, HTML)

    Open the audits/ folder. You should see:

        iam_policy_audit_report.json

        iam_policy_audit_report.csv

        iam_policy_audit_report.html

    JSON (iam_policy_audit_report.json):

[
  {
    "EntityType": "User",
    "EntityName": "DevOpsAdmin",
    "PolicyName": "AdministratorAccess",
    "PolicyType": "UserManaged",
    "Findings": [
      {
        "Sid": "",
        "Actions": ["*"],
        "Resources": ["*"]
      }
    ]
  },
  {
    "EntityType": "Role",
    "EntityName": "BackupRole",
    "PolicyName": "BackupPolicy",
    "PolicyType": "RoleInline",
    "Findings": [
      {
        "Sid": "StmtAllowAllS3",
        "Actions": ["s3:*"],
        "Resources": ["*"]
      }
    ]
  }
]

    Each object corresponds to a policy that had at least one overly broad statement.

CSV (iam_policy_audit_report.csv):

    EntityType,EntityName,PolicyName,PolicyType,Sid,Action,Resource
    User,DevOpsAdmin,AdministratorAccess,UserManaged,,*,*
    Role,BackupRole,BackupPolicy,RoleInline,StmtAllowAllS3,s3:*,*

        The first row (DevOpsAdmin) shows an empty Sid (no "Sid" field in the policy).

        Each wildcard combination becomes its own row.

    HTML (iam_policy_audit_report.html):

        Open it in a browser by double-clicking.

        You’ll see a styled table with alternating row colors, a summary of total flagged statements, and links to download JSON/CSV.

    Free Tier Note: All report files are generated locally; no AWS usage is involved in writing them.

SNS Email Alert

    Check the email you subscribed in Step 6. You should see an email from no-reply@sns.amazonaws.com.

    Subject:

⚠️ IAM Policy Auditor: Overly Broad Permissions Detected

Body:

    IAM Policy Auditor has detected 2 entities with overly broad permissions.

    JSON Report: audits/iam_policy_audit_report.json
    CSV Report: audits/iam_policy_audit_report.csv
    HTML Report: audits/iam_policy_audit_report.html

        These are the exact file paths on your local machine. If you want stakeholders to click links in the email, consider hosting the reports in an S3 bucket or a web server and updating the message accordingly.

    Free Tier Note (SNS Emails): As long as you stay under 100 000 email deliveries per month, SNS is free. Occasional alerts will not incur charges.

Troubleshooting & Common Pitfalls

    AWS CLI aws sts get-caller-identity Fails

        Cause: Incorrect AWS credentials or profile.

        Fix:

            Re-run aws configure.

            If using multiple profiles:

        > set AWS_PROFILE=auditor-user        # Windows
        # or
        $ export AWS_PROFILE=auditor-user     # macOS/Linux

“AccessDenied” Errors in main.py

    Symptom:

    botocore.exceptions.ClientError: An error occurred (AccessDenied) when calling the ListUsers operation: User is not authorized to perform: iam:ListUsers

    Cause: auditor-user lacks the required IAM permissions.

    Fix:

        In AWS Console → IAM → Users → auditor-user → Permissions → Inline policies, ensure the JSON from Step 1.3 is attached.

“NoSuchEntity” when Reading Policies

    Symptom:

    botocore.exceptions.ClientError: An error occurred (NoSuchEntity) when calling the GetUserPolicy operation: The user with name SomeUser cannot be found.

    Cause: The IAM entity was deleted or renamed mid-scan (rare).

    Fix:

        Re-run the script.

        For robustness, wrap each get_*_policy call in a try/except block to skip missing entities.

CSV File Is Empty

    Cause: audit_results was empty (no flagged policies). In this case, the CSV will contain only a header row. That is expected behavior.

    Fix:

        Inspect iam_policy_audit_report.json first—if it’s [], then no findings exist.

HTML Report Doesn’t Load or Styles Are Missing

    Cause: You might have copied only the HTML body without the <style> block, or your browser blocked local CSS.

    Fix:

        Verify that audits/iam_policy_audit_report.html begins with <!DOCTYPE html> and includes the <style> section in <head>.

        Open the file directly (e.g., right-click → “Open with → Chrome”).

SNS Email Never Arrives

    Cause 1: Subscription not confirmed.

    Cause 2: Incorrect SNS ARN in main.py.

    Cause 3: auditor-user lacks sns:Publish permission.

    Fix:

        In AWS Console → SNS → Subscriptions, ensure your email is Confirmed. If it’s “PendingConfirmation,” revisit the confirmation link.

        Copy the Topic ARN directly from SNS Console → Topics → your topic → ARN. Paste into src/main.py.

        In IAM Console → Users → auditor-user → Permissions, ensure sns:Publish is included in the inline policy.

Unit Tests Fail with ImportError

    Symptom:

ImportError: No module named src.main

Cause: Python cannot locate src/ as a module.

Fix (Option A): Set PYTHONPATH to include src/:

    Windows (Command Prompt):

(venv) > set PYTHONPATH=%cd%\src
(venv) > pytest --maxfail=1 --disable-warnings -q

macOS/Linux (bash):

    (venv) $ export PYTHONPATH=$(pwd)/src
    (venv) $ pytest --maxfail=1 --disable-warnings -q

Fix (Option B): Install the package in editable mode:

    Create a setup.py in the project root:

from setuptools import setup, find_packages

setup(
    name="aws-iam-policy-auditor",
    version="0.1.0",
    packages=find_packages(where="src"),
    package_dir={"": "src"},
)

Run:

            (venv) > pip install -e .
            (venv) > pytest --maxfail=1 --disable-warnings -q

Extra-Mile Modifications & Further Ideas

    Automatic Remediation

        Instead of just reporting, automatically tag or disable users/roles with overly broad policies (e.g., remove inline policies, attach a restricted “quarantine” policy).

        Warning: This can break production if used carelessly. Always test in a sandbox account.

    Lambda + EventBridge Scheduling

        Package the code as a Lambda function, then create an EventBridge rule to run it daily.

        Store results in an S3 bucket or DynamoDB. Only send an SNS alert if new findings appear.

        Free Tier:

            Lambda: 1 million free requests/month.

            EventBridge: 1 million free events/month.

            S3: 5 GB storage free, 20 000 GET requests free/month, 2 000 PUT requests free/month.

    Integration with AWS Config

        Use a Custom AWS Config Rule to evaluate IAM policies continuously.

        Trigger a Lambda on non-compliance that invokes this auditor logic.

        Free Tier:

            AWS Config: 1 000 recorded configuration items/month and 10 000 rule evaluations/month free.

    Dashboard with DynamoDB & React

        Write flagged results to a DynamoDB table.

        Build a React frontend (hosted on S3 + CloudFront) to visualize trends over time.

        Free Tier:

            DynamoDB: 25 GB storage free, 200 million reads/writes/month free (on-demand).

            S3: 5 GB storage free.

            CloudFront: 50 GB data transfer out free.

    Enhanced Policy Parsing

        Detect not only "Action": "*" but patterns like "Action": ["iam:Delete*"].

        Detect overly broad "Condition" clauses (e.g., "StringLike": {"aws:PrincipalArn": "*"}).

    Dockerization

        Create a Dockerfile so anyone can run:

> docker build -t iam-audit .
> docker run \
    -e AWS_ACCESS_KEY_ID=<key> \
    -e AWS_SECRET_ACCESS_KEY=<secret> \
    -e AWS_DEFAULT_REGION=us-east-1 \
    iam-audit

Example Dockerfile:

        FROM python:3.10-slim

        WORKDIR /app
        COPY requirements.txt .
        RUN pip install --upgrade pip && pip install -r requirements.txt

        COPY src/ ./src
        COPY audits/ ./audits

        ENV OUTPUT_JSON=audits/iam_policy_audit_report.json
        ENV OUTPUT_CSV=audits/iam_policy_audit_report.csv
        ENV OUTPUT_HTML=audits/iam_policy_audit_report.html
        ENV SNS_TOPIC_ARN=arn:aws:sns:us-east-1:123456789012:iam-audit-alerts

        ENTRYPOINT ["python", "src/main.py"]

        Running locally is free. If you deploy to ECS/EKS, consult AWS pricing.

    Custom Email Template (HTML Email)

        Use AWS SES for HTML-formatted emails. You’d need to verify sender/recipient addresses (SES sandbox).

        Publish SNS → Lambda → SES for richer email content.

        Free Tier (SES): 62 000 outbound emails/month free if sending from EC2. Otherwise, $0.10 per 1 000 emails.

License (MIT)

This project is licensed under the MIT License. See LICENSE for details.

MIT License

Copyright (c) 2025 <Ahmad>

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the “Software”), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:
