"""
Check: Access Keys Not Rotated
Flags IAM access keys that are older than 90 days.
Long-lived access keys are a significant security risk if leaked.
"""

from datetime import datetime, timezone


KEY_AGE_THRESHOLD_DAYS = 90


def check_old_keys(session):
    iam = session.client("iam")
    findings = []
    now = datetime.now(timezone.utc)

    try:
        paginator = iam.get_paginator("list_users")
        for page in paginator.paginate():
            for user in page["Users"]:
                username = user["UserName"]

                keys = iam.list_access_keys(UserName=username)["AccessKeyMetadata"]

                for key in keys:
                    key_id = key["AccessKeyId"]
                    status = key["Status"]
                    created = key["CreateDate"]
                    age_days = (now - created).days

                    if status == "Active" and age_days >= KEY_AGE_THRESHOLD_DAYS:
                        severity = "HIGH" if age_days >= 180 else "MEDIUM"
                        findings.append({
                            "check": "ACCESS_KEY_NOT_ROTATED",
                            "severity": severity,
                            "resource_type": "IAM Access Key",
                            "resource": f"{username} / {key_id[:8]}...",
                            "message": (
                                f"Access key for user '{username}' is {age_days} days old "
                                f"(created: {created.strftime('%Y-%m-%d')}). "
                                f"Keys should be rotated every {KEY_AGE_THRESHOLD_DAYS} days."
                            ),
                            "recommendation": (
                                "Rotate this access key: create a new key, update all services "
                                "using the old key, then deactivate and delete the old key."
                            )
                        })

                    elif status == "Inactive" and age_days >= KEY_AGE_THRESHOLD_DAYS:
                        findings.append({
                            "check": "ACCESS_KEY_NOT_ROTATED",
                            "severity": "LOW",
                            "resource_type": "IAM Access Key",
                            "resource": f"{username} / {key_id[:8]}...",
                            "message": (
                                f"Inactive access key for '{username}' is {age_days} days old. "
                                f"Old inactive keys should be cleaned up."
                            ),
                            "recommendation": "Delete this inactive access key to reduce clutter and risk."
                        })

    except Exception as e:
        findings.append({
            "check": "ACCESS_KEY_NOT_ROTATED",
            "severity": "ERROR",
            "resource_type": "IAM",
            "resource": "N/A",
            "message": f"Error running access key check: {str(e)}",
            "recommendation": "Ensure the role has iam:ListUsers and iam:ListAccessKeys permissions."
        })

    return findings
