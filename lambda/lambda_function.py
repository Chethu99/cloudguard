"""CloudGuard scanner: read-only AWS security checks -> findings.json in S3."""
import datetime
import json
import os

import boto3
from botocore.exceptions import ClientError

BUCKET = os.environ["SITE_BUCKET"]
WEIGHT = {"CRITICAL": 15, "HIGH": 8, "MEDIUM": 4, "LOW": 1}

# Control references: CIS AWS Foundations v3.0, SOC 2 TSC, ISO 27001:2022 Annex A, PCI DSS v4.0
CONTROLS = {
    "ROOT_MFA":   {"cis": "1.5",   "soc2": "CC6.1", "iso27001": "A.8.5",  "pci": "8.4"},
    "ROOT_KEYS":  {"cis": "1.4",   "soc2": "CC6.1", "iso27001": "A.8.2",  "pci": "7.2"},
    "USER_MFA":   {"cis": "1.10",  "soc2": "CC6.1", "iso27001": "A.8.5",  "pci": "8.4"},
    "KEY_AGE":    {"cis": "1.14",  "soc2": "CC6.2", "iso27001": "A.5.17", "pci": "8.6"},
    "PWD_POLICY": {"cis": "1.8",   "soc2": "CC6.1", "iso27001": "A.5.17", "pci": "8.3"},
    "S3_PUBLIC":  {"cis": "2.1.4", "soc2": "CC6.1", "iso27001": "A.8.3",  "pci": "1.4"},
    "SG_OPEN":    {"cis": "5.2",   "soc2": "CC6.6", "iso27001": "A.8.20", "pci": "1.3"},
    "EBS_ENC":    {"cis": "2.2.1", "soc2": "CC6.1", "iso27001": "A.8.24", "pci": "3.5"},
    "TRAIL":      {"cis": "3.1",   "soc2": "CC7.2", "iso27001": "A.8.15", "pci": "10.2"},
}


def mask(value):
    """The dashboard is public, so never publish full identifiers."""
    value = str(value)
    return value if len(value) <= 8 else value[:3] + "..." + value[-4:]


def add(findings, check, title, severity, resource, region, fix):
    findings.append({
        "check": check,
        "title": title,
        "severity": severity,
        "resource": mask(resource),
        "region": region,
        "remediation": fix,
        "controls": CONTROLS[check],
    })


def check_root(iam, findings):
    summary = iam.get_account_summary()["SummaryMap"]
    if summary.get("AccountMFAEnabled", 0) != 1:
        add(findings, "ROOT_MFA", "Root account has no MFA", "CRITICAL", "root", "global",
            "Enable an MFA device on the root user.")
    if summary.get("AccountAccessKeysPresent", 0) != 0:
        add(findings, "ROOT_KEYS", "Root account has access keys", "CRITICAL", "root", "global",
            "Delete root access keys and use IAM roles or users instead.")


def check_users(iam, findings):
    now = datetime.datetime.now(datetime.timezone.utc)
    for page in iam.get_paginator("list_users").paginate():
        for user in page["Users"]:
            name = user["UserName"]
            has_console = True
            try:
                iam.get_login_profile(UserName=name)
            except iam.exceptions.NoSuchEntityException:
                has_console = False
            if has_console and not iam.list_mfa_devices(UserName=name)["MFADevices"]:
                add(findings, "USER_MFA", "IAM user with console access has no MFA", "HIGH",
                    name, "global", "Assign an MFA device or remove console access.")
            for key in iam.list_access_keys(UserName=name)["AccessKeyMetadata"]:
                age = (now - key["CreateDate"]).days
                if key["Status"] == "Active" and age > 90:
                    add(findings, "KEY_AGE", "Access key older than 90 days (%d days)" % age,
                        "MEDIUM", name, "global", "Rotate the key, then delete the old one.")


def check_password_policy(iam, findings):
    try:
        policy = iam.get_account_password_policy()["PasswordPolicy"]
        if policy.get("MinimumPasswordLength", 0) < 14:
            add(findings, "PWD_POLICY", "Password policy minimum length is below 14", "MEDIUM",
                "account", "global", "Raise the minimum password length to 14 or more.")
    except iam.exceptions.NoSuchEntityException:
        add(findings, "PWD_POLICY", "No custom IAM password policy set", "MEDIUM",
            "account", "global", "Set a password policy with a minimum length of 14.")


def check_s3(s3, findings):
    for bucket in s3.list_buckets()["Buckets"]:
        name = bucket["Name"]
        try:
            cfg = s3.get_public_access_block(Bucket=name)["PublicAccessBlockConfiguration"]
            fully_blocked = all(cfg.values())
        except ClientError as err:
            if err.response["Error"]["Code"] == "NoSuchPublicAccessBlockConfiguration":
                fully_blocked = False
            else:
                continue  # could not read this bucket; skip rather than guess
        if not fully_blocked:
            add(findings, "S3_PUBLIC", "S3 bucket without full Block Public Access", "HIGH",
                name, "global", "Turn on all four Block Public Access settings for the bucket.")


def check_ec2(findings):
    regions = [r["RegionName"] for r in
               boto3.client("ec2", region_name="us-east-1").describe_regions()["Regions"]]
    for region in regions:
        ec2 = boto3.client("ec2", region_name=region)
        try:
            for page in ec2.get_paginator("describe_security_groups").paginate():
                for sg in page["SecurityGroups"]:
                    for perm in sg.get("IpPermissions", []):
                        open_v4 = any(r.get("CidrIp") == "0.0.0.0/0" for r in perm.get("IpRanges", []))
                        open_v6 = any(r.get("CidrIpv6") == "::/0" for r in perm.get("Ipv6Ranges", []))
                        if not (open_v4 or open_v6):
                            continue
                        proto = perm.get("IpProtocol")
                        low, high = perm.get("FromPort", 0), perm.get("ToPort", 65535)
                        if proto == "-1":
                            add(findings, "SG_OPEN", "Security group allows ALL traffic from the internet",
                                "CRITICAL", sg["GroupId"], region,
                                "Remove the 0.0.0.0/0 rule and allow only the ports and sources you need.")
                        elif proto == "tcp" and any(low <= p <= high for p in (22, 3389)):
                            add(findings, "SG_OPEN", "Security group exposes SSH/RDP to the internet",
                                "HIGH", sg["GroupId"], region,
                                "Restrict the source to a trusted IP range or use Session Manager.")
            for page in ec2.get_paginator("describe_volumes").paginate():
                for vol in page["Volumes"]:
                    if not vol["Encrypted"]:
                        add(findings, "EBS_ENC", "Unencrypted EBS volume", "MEDIUM",
                            vol["VolumeId"], region, "Snapshot, copy with encryption, and replace the volume.")
        except ClientError:
            continue


def check_cloudtrail(findings):
    trails = boto3.client("cloudtrail", region_name="us-east-1").describe_trails(
        includeShadowTrails=True)["trailList"]
    if not any(t.get("IsMultiRegionTrail") for t in trails):
        add(findings, "TRAIL", "No multi-region CloudTrail trail", "MEDIUM", "account", "us-east-1",
            "Create a multi-region trail that logs management events.")


def lambda_handler(event, context):
    iam = boto3.client("iam")
    s3 = boto3.client("s3")
    findings = []

    check_root(iam, findings)
    check_users(iam, findings)
    check_password_policy(iam, findings)
    check_s3(s3, findings)
    check_ec2(findings)
    check_cloudtrail(findings)

    penalty = sum(WEIGHT[f["severity"]] for f in findings)
    account_id = boto3.client("sts").get_caller_identity()["Account"]
    report = {
        "generated_at": datetime.datetime.now(datetime.timezone.utc).isoformat(timespec="seconds"),
        "account": "****" + account_id[-4:],
        "score": max(0, 100 - penalty),
        "summary": {s: sum(1 for f in findings if f["severity"] == s) for s in WEIGHT},
        "checks_run": len(CONTROLS),
        "findings": sorted(findings, key=lambda f: -WEIGHT[f["severity"]]),
    }
    s3.put_object(
        Bucket=BUCKET,
        Key="findings.json",
        Body=json.dumps(report).encode("utf-8"),
        ContentType="application/json",
        CacheControl="max-age=60",
    )
    return {"score": report["score"], "findings": len(findings)}
