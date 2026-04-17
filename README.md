# 🔐 IAM Misconfiguration Scanner

A Python CLI tool that scans AWS environments for IAM security misconfigurations and generates structured reports. Built to help security engineers identify and remediate identity-related risks before they become breaches.

---

## 🚨 What It Detects

| Check | Severity | Description |
|-------|----------|-------------|
| MFA Not Enabled | 🔴 HIGH | Console users without MFA configured |
| Overprivileged Policies | 🔴 HIGH | Policies granting wildcard `*` permissions |
| Public S3 Buckets | 🔴 HIGH | Buckets with Block Public Access disabled or public ACLs |
| Unused IAM Users | 🟡 MEDIUM | Users inactive for 90+ days |
| Unrotated Access Keys | 🟡 MEDIUM / 🔵 LOW | Active keys older than 90 days |

---

## 📸 Sample Output

```
============================================================
   🔐 IAM Misconfiguration Scanner
============================================================

[1/5] Checking MFA enforcement...
      → 1 finding(s)
[2/5] Checking for overprivileged policies...
      → 1 finding(s)
[3/5] Checking for unused/inactive users...
      → 1 finding(s)
[4/5] Checking access key rotation...
      → 2 finding(s)
[5/5] Checking S3 bucket public access...
      → 1 finding(s)

============================================================

FINDING                             SEVERITY   RESOURCE
-------------------------------------------------------------------------------------
MFA_NOT_ENABLED                     🔴 HIGH     dev-user-01
OVERPRIVILEGED_POLICY               🔴 HIGH     DevFullAccessPolicy
S3_PUBLIC_ACCESS_ENABLED            🔴 HIGH     my-app-assets-bucket
UNUSED_IAM_USER                     🟡 MEDIUM   temp-contractor-02
ACCESS_KEY_NOT_ROTATED              🟡 MEDIUM   dev-user-01 / AKIAIOSFOD...
ACCESS_KEY_NOT_ROTATED              🔵 LOW      old-service-account / AKIAI12345...
-------------------------------------------------------------------------------------

📊 Summary:  🔴 HIGH: 3   🟡 MEDIUM: 2   🔵 LOW: 1
⚠️  Action required — HIGH severity findings should be remediated immediately.

📄 JSON report saved → report.json
🌐 HTML report saved → report.html
```

---

## ⚙️ Installation

**Requirements:** Python 3.8+, AWS CLI configured

```bash
# Clone the repo
git clone https://github.com/aditi-chitnis/iam-scanner.git
cd iam-scanner

# Install dependencies
pip install -r requirements.txt

# Configure AWS credentials (if not already done)
aws configure
```

---

## 🚀 Usage

**Run all checks (default):**
```bash
python scanner.py
```

**Run specific checks only:**
```bash
python scanner.py --checks mfa policy s3
```

**Use a named AWS profile:**
```bash
python scanner.py --profile my-aws-profile
```

**Generate both JSON and HTML reports:**
```bash
python scanner.py --output results.json --html
```

**All options:**
```
--profile   AWS CLI profile name (default: default)
--output    Output JSON filename  (default: report.json)
--html      Also generate an HTML report
--checks    Specific checks: mfa | policy | unused | keys | s3 | all
```

---

## 📁 Project Structure

```
iam-scanner/
│
├── scanner.py              # Main CLI entry point
├── requirements.txt
├── sample_report.json      # Example output
│
├── checks/
│   ├── mfa_check.py        # MFA enforcement check
│   ├── policy_check.py     # Overprivileged policy check
│   ├── unused_users.py     # Inactive user check
│   ├── access_keys.py      # Key rotation check
│   └── s3_check.py         # S3 public access check
│
└── report/
    └── reporter.py         # Terminal output + JSON + HTML generation
```

---

## 🔑 Required AWS Permissions

The AWS user/role running this tool needs the following permissions:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "iam:ListUsers",
        "iam:GetLoginProfile",
        "iam:ListMFADevices",
        "iam:ListPolicies",
        "iam:GetPolicyVersion",
        "iam:ListAccessKeys",
        "s3:ListAllMyBuckets",
        "s3:GetBucketAcl",
        "s3:GetPublicAccessBlock",
        "sts:GetCallerIdentity"
      ],
      "Resource": "*"
    }
  ]
}
```

---

## 📄 Report Output

**JSON report** — machine-readable, suitable for automation pipelines:
```json
{
  "scan_timestamp": "2025-09-15T10:32:00Z",
  "total_findings": 6,
  "summary": { "HIGH": 3, "MEDIUM": 2, "LOW": 1, "ERROR": 0 },
  "findings": [ ... ]
}
```

**HTML report** — visual, shareable with teams. Each finding includes:
- Severity level
- Affected resource
- Detailed description
- Remediation recommendation

See [`sample_report.json`](./sample_report.json) for a full example.

---

## ⚠️ Disclaimer

This tool is intended for **authorized security auditing only**. Only run it against AWS accounts you own or have explicit written permission to scan. Unauthorized scanning of cloud environments may violate AWS Terms of Service and applicable laws.

---

## 👩‍💻 Author

**Aditi Chitnis** — Cyber-Security Engineer |  
[LinkedIn](https://linkedin.com/in/aditi-chitnis) · [GitHub](https://github.com/AditiChitnis05)
