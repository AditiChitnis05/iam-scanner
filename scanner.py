"""
IAM Misconfiguration Scanner
Author: Aditi Chitnis
Description: CLI tool to scan AWS environments for IAM security misconfigurations.
"""

import argparse
import boto3
from botocore.exceptions import NoCredentialsError, ProfileNotFound

from checks.mfa_check import check_mfa
from checks.policy_check import check_overprivileged
from checks.unused_users import check_unused_users
from checks.access_keys import check_old_keys
from checks.s3_check import check_public_buckets
from report.reporter import generate_report, print_summary


def run_scanner():
    parser = argparse.ArgumentParser(
        description="🔐 IAM Misconfiguration Scanner — Scan AWS for IAM security issues",
        formatter_class=argparse.RawTextHelpFormatter
    )
    parser.add_argument("--profile", default="default", help="AWS CLI profile name (default: default)")
    parser.add_argument("--output", default="report.json", help="Output JSON report filename (default: report.json)")
    parser.add_argument("--html", action="store_true", help="Also generate an HTML report")
    parser.add_argument(
        "--checks",
        nargs="+",
        choices=["mfa", "policy", "unused", "keys", "s3", "all"],
        default=["all"],
        help=(
            "Checks to run (default: all):\n"
            "  mfa     - Users with console access but no MFA\n"
            "  policy  - Overprivileged IAM policies (wildcard *)\n"
            "  unused  - IAM users inactive for 90+ days\n"
            "  keys    - Access keys not rotated in 90+ days\n"
            "  s3      - Publicly accessible S3 buckets\n"
            "  all     - Run all checks"
        )
    )
    args = parser.parse_args()

    # Connect to AWS
    try:
        session = boto3.Session(profile_name=args.profile)
        # Validate credentials early
        session.client("sts").get_caller_identity()
    except ProfileNotFound:
        print(f"\n❌ AWS profile '{args.profile}' not found. Run 'aws configure' first.\n")
        return
    except NoCredentialsError:
        print("\n❌ No AWS credentials found. Run 'aws configure' to set them up.\n")
        return
    except Exception as e:
        print(f"\n❌ Could not connect to AWS: {e}\n")
        return

    run_all = "all" in args.checks
    findings = []

    print("\n" + "=" * 60)
    print("   🔐 IAM Misconfiguration Scanner")
    print("=" * 60)

    if run_all or "mfa" in args.checks:
        print("\n[1/5] Checking MFA enforcement...")
        results = check_mfa(session)
        findings += results
        print(f"      → {len(results)} finding(s)")

    if run_all or "policy" in args.checks:
        print("[2/5] Checking for overprivileged policies...")
        results = check_overprivileged(session)
        findings += results
        print(f"      → {len(results)} finding(s)")

    if run_all or "unused" in args.checks:
        print("[3/5] Checking for unused/inactive users...")
        results = check_unused_users(session)
        findings += results
        print(f"      → {len(results)} finding(s)")

    if run_all or "keys" in args.checks:
        print("[4/5] Checking access key rotation...")
        results = check_old_keys(session)
        findings += results
        print(f"      → {len(results)} finding(s)")

    if run_all or "s3" in args.checks:
        print("[5/5] Checking S3 bucket public access...")
        results = check_public_buckets(session)
        findings += results
        print(f"      → {len(results)} finding(s)")

    print("\n" + "=" * 60)

    # Print terminal summary table
    print_summary(findings)

    # Save JSON report
    generate_report(findings, args.output, html=args.html)


if __name__ == "__main__":
    run_scanner()
