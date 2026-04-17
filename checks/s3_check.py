"""
Check: Publicly Accessible S3 Buckets
Flags S3 buckets that have public access enabled — either through
bucket ACLs, bucket policies, or disabled Block Public Access settings.
"""


def check_public_buckets(session):
    s3 = session.client("s3")
    findings = []

    try:
        buckets = s3.list_buckets().get("Buckets", [])

        for bucket in buckets:
            bucket_name = bucket["Name"]

            # Check 1: Block Public Access settings
            try:
                bpa = s3.get_public_access_block(Bucket=bucket_name)
                config = bpa["PublicAccessBlockConfiguration"]

                disabled_blocks = []
                if not config.get("BlockPublicAcls", True):
                    disabled_blocks.append("BlockPublicAcls")
                if not config.get("IgnorePublicAcls", True):
                    disabled_blocks.append("IgnorePublicAcls")
                if not config.get("BlockPublicPolicy", True):
                    disabled_blocks.append("BlockPublicPolicy")
                if not config.get("RestrictPublicBuckets", True):
                    disabled_blocks.append("RestrictPublicBuckets")

                if disabled_blocks:
                    findings.append({
                        "check": "S3_PUBLIC_ACCESS_ENABLED",
                        "severity": "HIGH",
                        "resource_type": "S3 Bucket",
                        "resource": bucket_name,
                        "message": (
                            f"Bucket '{bucket_name}' has Block Public Access disabled for: "
                            f"{', '.join(disabled_blocks)}. Data may be publicly readable."
                        ),
                        "recommendation": (
                            "Enable all four Block Public Access settings unless public access "
                            "is explicitly required for a static website."
                        )
                    })

            except s3.exceptions.NoSuchPublicAccessBlockConfiguration:
                # No block public access config = potentially public
                findings.append({
                    "check": "S3_PUBLIC_ACCESS_ENABLED",
                    "severity": "HIGH",
                    "resource_type": "S3 Bucket",
                    "resource": bucket_name,
                    "message": (
                        f"Bucket '{bucket_name}' has no Block Public Access configuration. "
                        f"It may be publicly accessible."
                    ),
                    "recommendation": "Apply Block Public Access settings to this bucket immediately."
                })
            except Exception:
                continue

            # Check 2: Bucket ACL — look for public grants
            try:
                acl = s3.get_bucket_acl(Bucket=bucket_name)
                public_uris = [
                    "http://acs.amazonaws.com/groups/global/AllUsers",
                    "http://acs.amazonaws.com/groups/global/AuthenticatedUsers"
                ]
                for grant in acl.get("Grants", []):
                    grantee = grant.get("Grantee", {})
                    if grantee.get("URI") in public_uris:
                        permission = grant.get("Permission", "UNKNOWN")
                        findings.append({
                            "check": "S3_PUBLIC_ACL",
                            "severity": "HIGH",
                            "resource_type": "S3 Bucket",
                            "resource": bucket_name,
                            "message": (
                                f"Bucket '{bucket_name}' ACL grants {permission} "
                                f"to '{grantee['URI'].split('/')[-1]}' (public group)."
                            ),
                            "recommendation": (
                                "Remove public ACL grants. Use bucket policies with "
                                "explicit principal restrictions instead."
                            )
                        })
            except Exception:
                continue

    except Exception as e:
        findings.append({
            "check": "S3_PUBLIC_ACCESS_ENABLED",
            "severity": "ERROR",
            "resource_type": "S3",
            "resource": "N/A",
            "message": f"Error running S3 check: {str(e)}",
            "recommendation": "Ensure the role has s3:ListAllMyBuckets, s3:GetBucketAcl, and s3:GetPublicAccessBlock permissions."
        })

    return findings
