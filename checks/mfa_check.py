"""
Check: MFA Not Enabled
Flags IAM users who have console (password) access but no MFA device attached.
"""


def check_mfa(session):
    iam = session.client("iam")
    findings = []

    try:
        paginator = iam.get_paginator("list_users")
        for page in paginator.paginate():
            for user in page["Users"]:
                username = user["UserName"]

                # Check if user has a console password (login profile)
                try:
                    iam.get_login_profile(UserName=username)
                    has_console = True
                except iam.exceptions.NoSuchEntityException:
                    has_console = False

                if not has_console:
                    continue  # programmatic-only user, skip

                # Check MFA devices
                mfa_devices = iam.list_mfa_devices(UserName=username)["MFADevices"]

                if len(mfa_devices) == 0:
                    findings.append({
                        "check": "MFA_NOT_ENABLED",
                        "severity": "HIGH",
                        "resource_type": "IAM User",
                        "resource": username,
                        "message": (
                            f"User '{username}' has AWS Console access but "
                            f"no MFA device is configured. This is a critical risk."
                        ),
                        "recommendation": "Enable MFA for this user immediately via IAM > Users > Security credentials."
                    })

    except Exception as e:
        findings.append({
            "check": "MFA_NOT_ENABLED",
            "severity": "ERROR",
            "resource_type": "IAM",
            "resource": "N/A",
            "message": f"Error running MFA check: {str(e)}",
            "recommendation": "Ensure the IAM role has iam:ListUsers and iam:ListMFADevices permissions."
        })

    return findings
