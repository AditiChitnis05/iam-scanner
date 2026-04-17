"""
Check: Overprivileged IAM Policies
Flags customer-managed policies that grant wildcard (*) actions or resources,
which effectively give admin-level access.
"""


def check_overprivileged(session):
    iam = session.client("iam")
    findings = []

    try:
        # Check customer-managed policies (Scope="Local")
        paginator = iam.get_paginator("list_policies")
        for page in paginator.paginate(Scope="Local"):
            for policy in page["Policies"]:
                policy_name = policy["PolicyName"]
                policy_arn = policy["Arn"]
                version_id = policy["DefaultVersionId"]

                try:
                    version = iam.get_policy_version(
                        PolicyArn=policy_arn,
                        VersionId=version_id
                    )["PolicyVersion"]["Document"]

                    for statement in version.get("Statement", []):
                        if statement.get("Effect") != "Allow":
                            continue

                        actions = statement.get("Action", [])
                        resources = statement.get("Resource", [])

                        if isinstance(actions, str):
                            actions = [actions]
                        if isinstance(resources, str):
                            resources = [resources]

                        wildcard_actions = [a for a in actions if "*" in a]
                        wildcard_resources = [r for r in resources if r == "*"]

                        if wildcard_actions and wildcard_resources:
                            findings.append({
                                "check": "OVERPRIVILEGED_POLICY",
                                "severity": "HIGH",
                                "resource_type": "IAM Policy",
                                "resource": policy_name,
                                "message": (
                                    f"Policy '{policy_name}' allows wildcard actions "
                                    f"({', '.join(wildcard_actions[:3])}) on all resources (*). "
                                    f"This grants effectively unrestricted access."
                                ),
                                "recommendation": (
                                    "Replace wildcard permissions with specific actions and resources "
                                    "following the principle of least privilege."
                                )
                            })
                        elif wildcard_actions:
                            findings.append({
                                "check": "OVERPRIVILEGED_POLICY",
                                "severity": "MEDIUM",
                                "resource_type": "IAM Policy",
                                "resource": policy_name,
                                "message": (
                                    f"Policy '{policy_name}' uses wildcard actions "
                                    f"({', '.join(wildcard_actions[:3])}) — review for least privilege."
                                ),
                                "recommendation": "Scope down actions to only what is required."
                            })

                except Exception:
                    continue  # skip if policy version can't be read

    except Exception as e:
        findings.append({
            "check": "OVERPRIVILEGED_POLICY",
            "severity": "ERROR",
            "resource_type": "IAM Policy",
            "resource": "N/A",
            "message": f"Error running policy check: {str(e)}",
            "recommendation": "Ensure the role has iam:ListPolicies and iam:GetPolicyVersion permissions."
        })

    return findings
