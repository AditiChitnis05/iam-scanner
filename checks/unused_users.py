"""
Check: Unused / Inactive IAM Users
Flags IAM users who have not logged in for 90+ days.
Inactive accounts are a common attack vector if compromised credentials exist.
"""

from datetime import datetime, timezone


INACTIVE_THRESHOLD_DAYS = 90


def check_unused_users(session):
    iam = session.client("iam")
    findings = []
    now = datetime.now(timezone.utc)

    try:
        paginator = iam.get_paginator("list_users")
        for page in paginator.paginate():
            for user in page["Users"]:
                username = user["UserName"]
                last_login = user.get("PasswordLastUsed")

                # Check if user has console access
                try:
                    iam.get_login_profile(UserName=username)
                    has_console = True
                except iam.exceptions.NoSuchEntityException:
                    has_console = False

                if not has_console:
                    continue

                if last_login is None:
                    # User has console access but has NEVER logged in
                    created = user["CreateDate"]
                    days_since_creation = (now - created).days

                    if days_since_creation > INACTIVE_THRESHOLD_DAYS:
                        findings.append({
                            "check": "UNUSED_IAM_USER",
                            "severity": "MEDIUM",
                            "resource_type": "IAM User",
                            "resource": username,
                            "message": (
                                f"User '{username}' has never logged in and was created "
                                f"{days_since_creation} days ago."
                            ),
                            "recommendation": (
                                "Verify if this account is still needed. "
                                "If not, disable or delete it."
                            )
                        })
                else:
                    days_inactive = (now - last_login).days
                    if days_inactive >= INACTIVE_THRESHOLD_DAYS:
                        findings.append({
                            "check": "UNUSED_IAM_USER",
                            "severity": "MEDIUM",
                            "resource_type": "IAM User",
                            "resource": username,
                            "message": (
                                f"User '{username}' has not logged in for {days_inactive} days "
                                f"(last login: {last_login.strftime('%Y-%m-%d')})."
                            ),
                            "recommendation": (
                                "Disable this account or confirm it is still required. "
                                "Stale accounts increase the attack surface."
                            )
                        })

    except Exception as e:
        findings.append({
            "check": "UNUSED_IAM_USER",
            "severity": "ERROR",
            "resource_type": "IAM",
            "resource": "N/A",
            "message": f"Error running unused users check: {str(e)}",
            "recommendation": "Ensure the role has iam:ListUsers and iam:GetLoginProfile permissions."
        })

    return findings
