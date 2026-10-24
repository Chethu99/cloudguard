# CloudGuard 🛡️

CloudGuard is a serverless, automated Cloud Security Posture Management (CSPM) and auditing platform built on AWS. It continuously scans AWS accounts for misconfigurations, maps risks to industry compliance frameworks, and visualizes security findings on an edge-delivered static dashboard—engineered entirely within the AWS Free Tier.

---

## Architecture Overview

```

       +-----------------------+

       | Amazon EventBridge    | (Cron: Every 6 Hours)

       +-----------+-----------+

                   |

                   v

       +-----------------------+

       | AWS Lambda (Python)   | <--- Read-Only Least-Privilege IAM Role

       +-----------+-----------+

                   |

     +-------------+-------------+

     | Scans AWS Infrastructure: |

     | - IAM (Keys, MFA, Root)   |

     | - Security Groups (0.0.0.0|

     | - S3 (Public access, Enc) |

     | - CloudTrail (Logging)    |

     +-------------+-------------+

                   |

                   v (Writes findings.json & posture score)

       +-----------------------+

       | Amazon S3 (Private)   |

       +-----------+-----------+

                   ^

                   | (Origin Access Control / Identity)

       +-----------+-----------+

       | Amazon CloudFront     |

       +-----------+-----------+

                   ^

                   | HTTPS

              [ Browser ]

```

---

## Key Features

- **Continuous Security Auditing:** A Python Lambda executes every 6 hours under a scoped, read-only IAM role to evaluate core AWS services:
  - **IAM:** Root account usage, MFA enforcement, stale access keys (>90 days), and unused credentials.

  - **Network / VPC:** Ingress security group rules exposing critical ports (`22`, `3389`, `80`, `443`) to `0.0.0.0/0`.

  - **Amazon S3:** Public bucket policies, public ACLs, S3 Block Public Access configurations, and server-side encryption.

  - **Amazon CloudTrail:** Multi-region logging, trail status, log file validation, and CloudWatch integration.

- **Multi-Standard Compliance Mapping:** Maps discovered risks and checks to controls across **CIS AWS Foundations Benchmark**, **SOC 2 Type II**, **ISO/IEC 27001**, and **PCI-DSS**.

- **Posture Scoring Engine:** Calculates an overall account security score ($0\text{--}100\%$) based on passing checks and outputs structured reports to `findings.json`.

- **Zero-Secret CI/CD (OIDC):** Deployments use GitHub Actions authenticated directly with AWS STS via **OpenID Connect (OIDC)** and `AssumeRoleWithWebIdentity`, eliminating static AWS access keys.

- **Policy-as-Code Quality Gate:** Integrated **AWS IAM Access Analyzer** validation in the delivery pipeline to automatically block deployments containing identity policy errors or security warnings.

- **Serverless & Free-Tier Native:** Built entirely on event-driven serverless architecture (Lambda, S3, CloudFront, EventBridge) with zero idle compute costs.

---

## Repository Layout

```

cloudguard/

├── .github/

│   └── workflows/

│       └── deploy.yml          # OIDC CI/CD deployment with IAM Access Analyzer gate

├── iam/

│   └── scanner-policy.json     # IAM policy checked by the CI/CD policy-as-code gate

├── lambda/

│   └── scanner.py              # Core Python audit logic, checks, and compliance mapping

├── site/

│   ├── index.html              # Static CSPM web dashboard

│   └── findings.json           # Latest evaluated audit payload and posture score

└── README.md

```

---

## Deployment & Pipeline Security

The GitHub Actions deployment pipeline adheres to DevSecOps best practices:

1. **Keyless STS Authentication:** Exchanges a short-lived GitHub Actions OIDC JWT for temporary AWS credentials scoped to the deployment role.

2. **Policy-as-Code Enforcement:** Validates identity policies with `aws accessanalyzer validate-policy`. Deployments fail immediately if any `ERROR` or `SECURITY_WARNING` findings are detected.

3. **Targeted Asset Synchronization:** Syncs the static dashboard files to the private S3 bucket while preserving runtime reports using `--exclude "findings.json"`.

4. **Edge Cache Invalidation:** Automatically issues a cache invalidation request to CloudFront to serve the updated dashboard globally.

---

## The Lifecycle: Detect → Prioritize → Fix → Verify

CloudGuard creates an automated verification loop:

1. **Detect:** EventBridge triggers the auditing Lambda; any misconfiguration is identified and logged to `findings.json`.

2. **Prioritize:** The dashboard highlights findings by severity (Critical, High, Medium, Low) and displays corresponding compliance control impacts.

3. **Fix:** Remediate the issue directly in AWS (e.g., enable S3 Block Public Access or close SSH to the internet).

4. **Verify:** Re-run the scanner or wait for the next scheduled execution to verify that the finding clears and the posture score recovers to 100%.

---

## License

This project is licensed under the MIT License.
