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
# Output paths (the audits/ folder)
OUTPUT_JSON = "audits/iam_policy_audit_report.json"
OUTPUT_CSV  = "audits/iam_policy_audit_report.csv"
OUTPUT_HTML = "audits/iam_policy_audit_report.html"

# SNS Topic ARN for alerts (paste the ARN you copied earlier)
SNS_TOPIC_ARN = "arn:aws:sns:us-east-2:495599753252:iam-audit-alerts"
# ------------------------------

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
    # Normalize single-statement (dict) into a list
    if not isinstance(statements, list):
        statements = [statements]

    for stmt in statements:
        if stmt.get("Effect", "") == "Allow":
            actions = stmt.get("Action", [])
            resources = stmt.get("Resource", [])
            # Normalize strings to lists
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
