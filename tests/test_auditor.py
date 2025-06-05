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
