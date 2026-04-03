"""
Framework Mapping — Maps CIS check IDs to equivalent NIST 800-53 Rev 5 and CSA CCM v4.1 controls.

Every security check the scanner runs is originally tagged with a CIS rule ID.
When the user requests a report for NIST or CCM, this module re-labels the same
findings with the correct control ID, title, and framework reference so the report
is accurate to the selected framework.

Structure per entry:
  "CIS_RULE_ID": {
      "NIST": {
          "rule_id": "NIST XX-N",
          "title": "Control Name",
          "description": "Framework-accurate description",
          "recommendation": "Framework-accurate recommendation",
          "doc_url": "https://csrc.nist.gov/...",
      },
      "CCM": {
          "rule_id": "DOM-NN",
          "title": "Control Name",
          ...
      }
  }
"""

# ─────────────────────────────────────────────────────────────────────────────
# Mapping: CIS Rule ID → {NIST: {...}, CCM: {...}}
# ─────────────────────────────────────────────────────────────────────────────

FRAMEWORK_MAPPING = {

    # ── S3 / Storage ──────────────────────────────────────────────────────────

    "CIS 2.1.1": {
        "NIST": {
            "rule_id": "NIST SC-28",
            "title": "Protection of Information at Rest",
            "description": "The system must protect the confidentiality and integrity of information at rest. S3 bucket data must be encrypted using AES-256 or KMS.",
            "recommendation": "Enable default server-side encryption on the S3 bucket using SSE-S3 (AES-256) or SSE-KMS. NIST SC-28 requires encryption of data at rest for all storage containing sensitive information.",
            "doc_url": "https://csrc.nist.gov/projects/cprt/catalog#/cprt/framework/version/SP_800_53_5_1_1/home?element=SC-28",
        },
        "CCM": {
            "rule_id": "CEK-03",
            "title": "Data Encryption",
            "description": "CSA CCM CEK-03 requires cryptographic controls to protect data at rest. S3 bucket must have server-side encryption enabled.",
            "recommendation": "Enable S3 default encryption (SSE-S3 or SSE-KMS). CEK-03 mandates AES-256 or equivalent encryption for all stored data. Use customer-managed keys (CEK-06) where possible.",
            "doc_url": "https://cloudsecurityalliance.org/research/cloud-controls-matrix",
        },
    },

    "CIS 2.1.2": {
        "NIST": {
            "rule_id": "NIST CP-9",
            "title": "System Backup",
            "description": "Conduct backups of user-level information. S3 versioning provides a form of data backup by preserving all object versions.",
            "recommendation": "Enable S3 versioning to support data recovery in line with NIST CP-9. Set a lifecycle policy to manage version retention costs.",
            "doc_url": "https://csrc.nist.gov/projects/cprt/catalog#/cprt/framework/version/SP_800_53_5_1_1/home?element=CP-9",
        },
        "CCM": {
            "rule_id": "BCR-08",
            "title": "Backup and Recovery Testing",
            "description": "CSA CCM BCR-08 requires backup and recovery procedures to ensure data availability. S3 versioning supports recovery of accidentally deleted or overwritten objects.",
            "recommendation": "Enable S3 versioning to comply with CCM BCR-08. Test restore procedures periodically. Add object lock for immutable backup compliance.",
            "doc_url": "https://cloudsecurityalliance.org/research/cloud-controls-matrix",
        },
    },

    "CIS 2.1.5": {
        "NIST": {
            "rule_id": "NIST AC-3",
            "title": "Access Enforcement",
            "description": "Enforce approved authorizations for logical access. S3 public access block prevents unauthorized public access to bucket data.",
            "recommendation": "Enable all four S3 public access block settings. NIST AC-3 requires enforcing access control policies — public access must be explicitly blocked unless a documented business requirement exists.",
            "doc_url": "https://csrc.nist.gov/projects/cprt/catalog#/cprt/framework/version/SP_800_53_5_1_1/home?element=AC-3",
        },
        "CCM": {
            "rule_id": "DSP-10",
            "title": "Sensitive Data Protection",
            "description": "CCM DSP-10 requires protecting sensitive data through access controls throughout its lifecycle. S3 public access must be blocked to prevent unintended data exposure.",
            "recommendation": "Enable all four S3 public access block settings. CCM DSP-10 requires classification and access control enforcement. Tag buckets with data classification and block all public access.",
            "doc_url": "https://cloudsecurityalliance.org/research/cloud-controls-matrix",
        },
    },

    "CIS 3.6": {
        "NIST": {
            "rule_id": "NIST AU-2",
            "title": "Event Logging",
            "description": "Identify events the system must be capable of logging. S3 server access logging captures all requests made to the bucket for audit purposes.",
            "recommendation": "Enable S3 server access logging to a dedicated logging bucket. NIST AU-2 requires logging of data access events for sensitive storage.",
            "doc_url": "https://csrc.nist.gov/projects/cprt/catalog#/cprt/framework/version/SP_800_53_5_1_1/home?element=AU-2",
        },
        "CCM": {
            "rule_id": "LOG-05",
            "title": "Audit Logging",
            "description": "CCM LOG-05 requires logging of all data access events. S3 access logging provides an audit trail of bucket requests.",
            "recommendation": "Enable S3 server access logging. CCM LOG-05 mandates comprehensive audit logging including data access. Send logs to a centralized SIEM.",
            "doc_url": "https://cloudsecurityalliance.org/research/cloud-controls-matrix",
        },
    },

    # ── Security Groups / Networking ─────────────────────────────────────────

    "CIS 5.1": {
        "NIST": {
            "rule_id": "NIST SC-7",
            "title": "Boundary Protection",
            "description": "Monitor and control communications at external boundaries. A security group allowing all inbound traffic (0.0.0.0/0, all ports) violates boundary protection requirements.",
            "recommendation": "Remove all-traffic ingress rules immediately. NIST SC-7 requires restricting network access at system boundaries. Restrict each port to known trusted source IP ranges.",
            "doc_url": "https://csrc.nist.gov/projects/cprt/catalog#/cprt/framework/version/SP_800_53_5_1_1/home?element=SC-7",
        },
        "CCM": {
            "rule_id": "I&S-07",
            "title": "Network Security",
            "description": "CCM I&S-07 requires network security controls including firewalls and least-privilege access. Allowing all traffic from the internet violates this control.",
            "recommendation": "Remove unrestricted ingress rules. CCM I&S-07 requires implementing firewalls and micro-segmentation. Apply zero-trust principles — deny all, permit only required traffic.",
            "doc_url": "https://cloudsecurityalliance.org/research/cloud-controls-matrix",
        },
    },

    "CIS 5.2": {
        "NIST": {
            "rule_id": "NIST AC-17",
            "title": "Remote Access",
            "description": "Establish configuration requirements for remote access. SSH (port 22) exposed to 0.0.0.0/0 violates remote access control requirements.",
            "recommendation": "Restrict SSH to VPN CIDRs or bastion host IPs. NIST AC-17 requires controlling all remote access. Use AWS Systems Manager Session Manager as an MFA-enforced alternative.",
            "doc_url": "https://csrc.nist.gov/projects/cprt/catalog#/cprt/framework/version/SP_800_53_5_1_1/home?element=AC-17",
        },
        "CCM": {
            "rule_id": "I&S-07",
            "title": "Network Security",
            "description": "CCM I&S-07 requires network security controls. SSH (port 22) open to the internet exposes the instance to brute-force and exploitation attacks.",
            "recommendation": "Restrict SSH to specific trusted IPs. CCM I&S-07 mandates micro-segmentation. Use AWS Systems Manager Session Manager or a VPN-protected bastion host.",
            "doc_url": "https://cloudsecurityalliance.org/research/cloud-controls-matrix",
        },
    },

    "CIS 5.3": {
        "NIST": {
            "rule_id": "NIST AC-17",
            "title": "Remote Access",
            "description": "Establish configuration requirements for remote access. RDP (port 3389) exposed to 0.0.0.0/0 violates remote access control requirements.",
            "recommendation": "Restrict RDP access to specific trusted IPs. NIST AC-17 requires controlling remote access with MFA enforcement. Use AWS Fleet Manager or VPN.",
            "doc_url": "https://csrc.nist.gov/projects/cprt/catalog#/cprt/framework/version/SP_800_53_5_1_1/home?element=AC-17",
        },
        "CCM": {
            "rule_id": "I&S-07",
            "title": "Network Security",
            "description": "CCM I&S-07 requires network security controls. RDP (port 3389) open to the internet is a prime target for ransomware and brute-force attacks.",
            "recommendation": "Restrict RDP to trusted IPs only. CCM I&S-07 mandates boundary protection. Use AWS Fleet Manager for secure RDP without exposing port 3389.",
            "doc_url": "https://cloudsecurityalliance.org/research/cloud-controls-matrix",
        },
    },

    "CIS 5.4": {
        "NIST": {
            "rule_id": "NIST SC-7",
            "title": "Boundary Protection",
            "description": "Database ports (MySQL 3306, PostgreSQL 5432, MSSQL 1433, MongoDB 27017) must not be exposed to the internet. NIST SC-7 requires subnetworks for publicly accessible components.",
            "recommendation": "Remove database port rules from internet-facing security groups. NIST SC-7 requires placing databases in private subnets behind application-tier security groups.",
            "doc_url": "https://csrc.nist.gov/projects/cprt/catalog#/cprt/framework/version/SP_800_53_5_1_1/home?element=SC-7",
        },
        "CCM": {
            "rule_id": "I&S-07",
            "title": "Network Security",
            "description": "CCM I&S-07 requires network segmentation. Database ports exposed to the internet represent a critical misconfiguration enabling direct database attacks.",
            "recommendation": "Restrict database ports to application-tier security groups. CCM I&S-07 mandates micro-segmentation — databases must only be reachable from the application layer.",
            "doc_url": "https://cloudsecurityalliance.org/research/cloud-controls-matrix",
        },
    },

    # ── IAM Policies ─────────────────────────────────────────────────────────

    "CIS 1.16": {
        "NIST": {
            "rule_id": "NIST AC-6",
            "title": "Least Privilege",
            "description": "Employ the principle of least privilege. IAM policies granting Action:* on Resource:* provide unrestricted access violating least-privilege requirements.",
            "recommendation": "Replace wildcard policies with specific service actions. NIST AC-6 requires scoping all access to the minimum necessary. Use AWS IAM Access Analyzer to identify over-permissive policies.",
            "doc_url": "https://csrc.nist.gov/projects/cprt/catalog#/cprt/framework/version/SP_800_53_5_1_1/home?element=AC-6",
        },
        "CCM": {
            "rule_id": "IAM-01",
            "title": "Identity and Access Management Policy",
            "description": "CCM IAM-01 requires implementing least-privilege access. IAM policies with full admin access (*:*) violate the principle of minimum necessary access.",
            "recommendation": "Replace full admin policies with specific action grants. CCM IAM-01 requires periodic access reviews and least-privilege enforcement. Remove or scope down wildcard policies.",
            "doc_url": "https://cloudsecurityalliance.org/research/cloud-controls-matrix",
        },
    },

    "CIS 1.22": {
        "NIST": {
            "rule_id": "NIST AC-6",
            "title": "Least Privilege",
            "description": "Employ the principle of least privilege for all IAM policies. Granting all actions for a service (e.g., s3:*) is overly permissive.",
            "recommendation": "Replace service-wide wildcard actions with specific API actions needed. NIST AC-6 requires granting only what is explicitly needed, not all actions for a service.",
            "doc_url": "https://csrc.nist.gov/projects/cprt/catalog#/cprt/framework/version/SP_800_53_5_1_1/home?element=AC-6",
        },
        "CCM": {
            "rule_id": "IAM-09",
            "title": "User Access Reviews",
            "description": "CCM IAM-09 requires periodic review of user access rights. Overly broad IAM policies (service:*) should be identified and remediated during access reviews.",
            "recommendation": "Replace service wildcard actions with specific permissions. CCM IAM-09 requires quarterly access reviews — this finding should be remediated and validated in the next access review cycle.",
            "doc_url": "https://cloudsecurityalliance.org/research/cloud-controls-matrix",
        },
    },

    # ── IAM Users ────────────────────────────────────────────────────────────

    "CIS 1.10": {
        "NIST": {
            "rule_id": "NIST IA-2",
            "title": "Identification and Authentication (Organizational Users)",
            "description": "Uniquely identify and authenticate organizational users and implement multi-factor authentication for privileged and non-privileged accounts.",
            "recommendation": "Enable MFA for this IAM user immediately. NIST IA-2 requires MFA for all users with console access. Use virtual MFA (Google Authenticator) or hardware keys (YubiKey).",
            "doc_url": "https://csrc.nist.gov/projects/cprt/catalog#/cprt/framework/version/SP_800_53_5_1_1/home?element=IA-2",
        },
        "CCM": {
            "rule_id": "IAM-07",
            "title": "Multi-Factor Authentication",
            "description": "CCM IAM-07 requires MFA for all user access to cloud management consoles and privileged accounts. This user has no MFA device configured.",
            "recommendation": "Enable MFA immediately. CCM IAM-07 mandates MFA for all console logins. Use FIDO2/WebAuthn hardware keys for privileged accounts. Audit MFA compliance monthly.",
            "doc_url": "https://cloudsecurityalliance.org/research/cloud-controls-matrix",
        },
    },

    "CIS 1.14": {
        "NIST": {
            "rule_id": "NIST IA-5",
            "title": "Authenticator Management",
            "description": "Manage system authenticators by enforcing rotation. Access keys older than 90 days represent long-lived credentials that increase compromise risk.",
            "recommendation": "Rotate this access key immediately. NIST IA-5 requires rotating credentials on a defined schedule. Create a new key, update all applications, then deactivate and delete the old key.",
            "doc_url": "https://csrc.nist.gov/projects/cprt/catalog#/cprt/framework/version/SP_800_53_5_1_1/home?element=IA-5",
        },
        "CCM": {
            "rule_id": "IAM-02",
            "title": "Strong Password Policy and Procedures",
            "description": "CCM IAM-02 requires enforcing credential rotation policies. Access keys exceeding 90 days violate the credential lifecycle management requirement.",
            "recommendation": "Rotate the access key now. CCM IAM-02 requires 90-day key rotation. Create a new key, update consuming services, deactivate the old key, then delete it after 7 days.",
            "doc_url": "https://cloudsecurityalliance.org/research/cloud-controls-matrix",
        },
    },

    # ── EC2 ──────────────────────────────────────────────────────────────────

    "EC2.1": {
        "NIST": {
            "rule_id": "NIST AC-6",
            "title": "Least Privilege",
            "description": "EC2 instances should use IAM roles (instance profiles) rather than hardcoded credentials. Instance profiles apply least-privilege access for compute workloads.",
            "recommendation": "Attach an IAM instance profile with minimum required permissions. NIST AC-6 requires avoiding long-lived credentials — use IAM roles for EC2 instead.",
            "doc_url": "https://csrc.nist.gov/projects/cprt/catalog#/cprt/framework/version/SP_800_53_5_1_1/home?element=AC-6",
        },
        "CCM": {
            "rule_id": "IAM-01",
            "title": "Identity and Access Management Policy",
            "description": "CCM IAM-01 requires workloads to use managed identities. EC2 without an instance profile may rely on hardcoded credentials, violating IAM policy.",
            "recommendation": "Attach an IAM instance profile. CCM IAM-01 requires all workloads to use managed identity mechanisms — IAM roles for EC2 are the AWS-native implementation.",
            "doc_url": "https://cloudsecurityalliance.org/research/cloud-controls-matrix",
        },
    },

    "EC2.2": {
        "NIST": {
            "rule_id": "NIST SC-7",
            "title": "Boundary Protection",
            "description": "EC2 instances with public IP addresses increase the attack surface. NIST SC-7 requires network boundary controls that limit direct internet exposure.",
            "recommendation": "Remove the public IP if not required. NIST SC-7 recommends using load balancers or NAT gateways for internet access instead of direct public IPs.",
            "doc_url": "https://csrc.nist.gov/projects/cprt/catalog#/cprt/framework/version/SP_800_53_5_1_1/home?element=SC-7",
        },
        "CCM": {
            "rule_id": "I&S-07",
            "title": "Network Security",
            "description": "CCM I&S-07 requires minimizing the attack surface. EC2 instances with public IPs are directly reachable from the internet, increasing exposure.",
            "recommendation": "Use private IPs only and route through a load balancer or NAT gateway. CCM I&S-07 mandates network segmentation — public-facing instances should be behind a WAF/ALB.",
            "doc_url": "https://cloudsecurityalliance.org/research/cloud-controls-matrix",
        },
    },

    # ── RDS ──────────────────────────────────────────────────────────────────

    "RDS.1": {
        "NIST": {
            "rule_id": "NIST SC-7",
            "title": "Boundary Protection",
            "description": "Databases must not be directly accessible from the internet. NIST SC-7 requires placing databases in private subnets behind boundary protection controls.",
            "recommendation": "Set RDS PubliclyAccessible=False. NIST SC-7 requires databases to reside in private network segments accessible only through application-tier controls.",
            "doc_url": "https://csrc.nist.gov/projects/cprt/catalog#/cprt/framework/version/SP_800_53_5_1_1/home?element=SC-7",
        },
        "CCM": {
            "rule_id": "I&S-07",
            "title": "Network Security",
            "description": "CCM I&S-07 requires network segmentation for data stores. A publicly accessible RDS instance violates the requirement to keep data stores in protected network segments.",
            "recommendation": "Disable public accessibility on RDS. CCM I&S-07 requires databases to be isolated in private subnets. Access only through application-tier security groups.",
            "doc_url": "https://cloudsecurityalliance.org/research/cloud-controls-matrix",
        },
    },

    "RDS.2": {
        "NIST": {
            "rule_id": "NIST SC-28",
            "title": "Protection of Information at Rest",
            "description": "The system must protect the confidentiality of database data at rest using cryptographic mechanisms. RDS without encryption violates this requirement.",
            "recommendation": "Enable RDS storage encryption. NIST SC-28 requires encryption of all data at rest. Note: encryption must be enabled at creation time — snapshot and restore to an encrypted instance.",
            "doc_url": "https://csrc.nist.gov/projects/cprt/catalog#/cprt/framework/version/SP_800_53_5_1_1/home?element=SC-28",
        },
        "CCM": {
            "rule_id": "CEK-03",
            "title": "Data Encryption",
            "description": "CCM CEK-03 requires data at rest to be encrypted using industry-standard algorithms. RDS without storage encryption exposes database contents to unauthorized hardware access.",
            "recommendation": "Enable RDS encryption at rest using AWS KMS. CCM CEK-03 mandates AES-256 encryption for stored data. Use customer-managed KMS keys (CMKs) for audit trail and rotation.",
            "doc_url": "https://cloudsecurityalliance.org/research/cloud-controls-matrix",
        },
    },

    # ── Lambda ───────────────────────────────────────────────────────────────

    "LAM.1": {
        "NIST": {
            "rule_id": "NIST CM-6",
            "title": "Configuration Settings",
            "description": "Establish and document configuration settings for IT products. Lambda functions running on end-of-life runtimes violate secure configuration baseline requirements.",
            "recommendation": "Update Lambda runtime to a currently supported version. NIST CM-6 requires applying security configuration baselines — outdated runtimes are out of baseline.",
            "doc_url": "https://csrc.nist.gov/projects/cprt/catalog#/cprt/framework/version/SP_800_53_5_1_1/home?element=CM-6",
        },
        "CCM": {
            "rule_id": "TVM-02",
            "title": "Vulnerability Management Policy",
            "description": "CCM TVM-02 requires patching vulnerabilities within defined SLOs. Outdated Lambda runtimes are end-of-life and may contain unpatched security vulnerabilities.",
            "recommendation": "Update Lambda runtime immediately. CCM TVM-02 treats end-of-life software as a HIGH vulnerability requiring remediation within 7 days.",
            "doc_url": "https://cloudsecurityalliance.org/research/cloud-controls-matrix",
        },
    },

    # ── VPC ──────────────────────────────────────────────────────────────────

    "VPC.1": {
        "NIST": {
            "rule_id": "NIST CM-2",
            "title": "Baseline Configuration",
            "description": "Maintain baseline configurations for information systems. Using the default VPC means the network baseline is not under organizational control.",
            "recommendation": "Migrate workloads to a custom VPC. NIST CM-2 requires maintaining documented, controlled baseline configurations — the default VPC is not a controlled baseline.",
            "doc_url": "https://csrc.nist.gov/projects/cprt/catalog#/cprt/framework/version/SP_800_53_5_1_1/home?element=CM-2",
        },
        "CCM": {
            "rule_id": "CCC-01",
            "title": "Change Management Policy",
            "description": "CCM CCC-01 requires controlled configuration management. Default VPCs have pre-configured settings that may not align with organizational security policy.",
            "recommendation": "Create a custom VPC with documented CIDR ranges, subnet design, and flow log configuration. CCM CCC-01 requires all production infrastructure to be under change management control.",
            "doc_url": "https://cloudsecurityalliance.org/research/cloud-controls-matrix",
        },
    },

    # ── IaC / CIS Terraform rule IDs (short form without "CIS " prefix) ───────
    # These are generated by rule_engine.py and use bare numeric IDs.
    # We add them as alias keys that map to the same framework data.

    "2.1.2": {
        "NIST": {
            "rule_id": "NIST CP-9",
            "title": "System Backup",
            "description": "Conduct backups of user-level information. S3 versioning provides data recovery by preserving all object versions.",
            "recommendation": "Enable S3 versioning to support data recovery in line with NIST CP-9. Set a lifecycle policy to manage version retention costs.",
            "doc_url": "https://csrc.nist.gov/projects/cprt/catalog#/cprt/framework/version/SP_800_53_5_1_1/home?element=CP-9",
        },
        "CCM": {
            "rule_id": "BCR-08",
            "title": "Backup and Recovery Testing",
            "description": "CSA CCM BCR-08 requires backup and recovery procedures. S3 versioning supports recovery of accidentally deleted or overwritten objects.",
            "recommendation": "Enable S3 versioning to comply with CCM BCR-08. Test restore procedures periodically. Add object lock for immutable backup compliance.",
            "doc_url": "https://cloudsecurityalliance.org/research/cloud-controls-matrix",
        },
    },

    "2.1.4": {
        "NIST": {
            "rule_id": "NIST AC-3",
            "title": "Access Enforcement",
            "description": "Enforce approved authorizations for logical access. S3 public access block prevents unauthorized public access to bucket data.",
            "recommendation": "Enable all four S3 public access block settings. NIST AC-3 requires enforcing access control policies — public access must be explicitly blocked unless documented.",
            "doc_url": "https://csrc.nist.gov/projects/cprt/catalog#/cprt/framework/version/SP_800_53_5_1_1/home?element=AC-3",
        },
        "CCM": {
            "rule_id": "DSP-10",
            "title": "Sensitive Data Protection",
            "description": "CCM DSP-10 requires protecting sensitive data through access controls. S3 public access must be blocked to prevent unintended data exposure.",
            "recommendation": "Enable all four S3 public access block settings. CCM DSP-10 requires classification and access control enforcement. Block all public access.",
            "doc_url": "https://cloudsecurityalliance.org/research/cloud-controls-matrix",
        },
    },

    "2.1.5": {
        "NIST": {
            "rule_id": "NIST CP-9",
            "title": "System Backup",
            "description": "S3 versioning must be enabled to ensure data can be recovered from accidental deletion or overwrites, as required by NIST CP-9 backup controls.",
            "recommendation": "Enable S3 versioning. NIST CP-9 requires backup capabilities — versioning ensures all object versions are retained for recovery.",
            "doc_url": "https://csrc.nist.gov/projects/cprt/catalog#/cprt/framework/version/SP_800_53_5_1_1/home?element=CP-9",
        },
        "CCM": {
            "rule_id": "BCR-08",
            "title": "Backup and Recovery Testing",
            "description": "CCM BCR-08 requires backup and recovery procedures. S3 versioning provides object-level recovery for compliance with data protection requirements.",
            "recommendation": "Enable S3 versioning. CCM BCR-08 requires tested recovery procedures — versioning enables point-in-time recovery for all objects.",
            "doc_url": "https://cloudsecurityalliance.org/research/cloud-controls-matrix",
        },
    },

    "4.1": {
        "NIST": {
            "rule_id": "NIST AC-17",
            "title": "Remote Access",
            "description": "SSH (port 22) must not be exposed to 0.0.0.0/0. NIST AC-17 requires controlling all remote access sessions with documented configuration requirements.",
            "recommendation": "Restrict SSH to VPN CIDRs or bastion host IPs. NIST AC-17 requires controlling remote access. Use AWS Systems Manager Session Manager as an MFA-enforced alternative.",
            "doc_url": "https://csrc.nist.gov/projects/cprt/catalog#/cprt/framework/version/SP_800_53_5_1_1/home?element=AC-17",
        },
        "CCM": {
            "rule_id": "I&S-07",
            "title": "Network Security",
            "description": "CCM I&S-07 requires network security controls. SSH (port 22) open to the internet exposes the instance to brute-force and exploitation attacks.",
            "recommendation": "Restrict SSH to specific trusted IPs. CCM I&S-07 mandates micro-segmentation. Use AWS Systems Manager Session Manager or a VPN-protected bastion host.",
            "doc_url": "https://cloudsecurityalliance.org/research/cloud-controls-matrix",
        },
    },

    "4.2": {
        "NIST": {
            "rule_id": "NIST AC-17",
            "title": "Remote Access",
            "description": "RDP (port 3389) must not be exposed to 0.0.0.0/0. NIST AC-17 requires controlling remote access sessions with MFA enforcement.",
            "recommendation": "Restrict RDP access to specific trusted IPs. NIST AC-17 requires controlling remote access with MFA. Use AWS Fleet Manager or VPN.",
            "doc_url": "https://csrc.nist.gov/projects/cprt/catalog#/cprt/framework/version/SP_800_53_5_1_1/home?element=AC-17",
        },
        "CCM": {
            "rule_id": "I&S-07",
            "title": "Network Security",
            "description": "CCM I&S-07 requires network security controls. RDP (port 3389) open to the internet is a prime target for ransomware and brute-force attacks.",
            "recommendation": "Restrict RDP to trusted IPs only. CCM I&S-07 mandates boundary protection. Use AWS Fleet Manager for secure RDP without exposing port 3389.",
            "doc_url": "https://cloudsecurityalliance.org/research/cloud-controls-matrix",
        },
    },

    "4.3": {
        "NIST": {
            "rule_id": "NIST SC-7",
            "title": "Boundary Protection",
            "description": "High-risk ports (databases, admin interfaces) must not be exposed to the internet. NIST SC-7 requires restricting network access at system boundaries.",
            "recommendation": "Remove internet-facing rules for high-risk ports. NIST SC-7 requires placing services in private subnets behind boundary protection controls.",
            "doc_url": "https://csrc.nist.gov/projects/cprt/catalog#/cprt/framework/version/SP_800_53_5_1_1/home?element=SC-7",
        },
        "CCM": {
            "rule_id": "I&S-07",
            "title": "Network Security",
            "description": "CCM I&S-07 requires network segmentation. High-risk ports exposed to the internet represent critical misconfigurations that enable direct attacks.",
            "recommendation": "Restrict high-risk ports to application-tier security groups. CCM I&S-07 mandates micro-segmentation — services must only be reachable from known, controlled sources.",
            "doc_url": "https://cloudsecurityalliance.org/research/cloud-controls-matrix",
        },
    },

    "2.3.1": {
        "NIST": {
            "rule_id": "NIST SC-28",
            "title": "Protection of Information at Rest",
            "description": "RDS database storage must be encrypted. NIST SC-28 requires protection of the confidentiality of database data at rest using cryptographic mechanisms.",
            "recommendation": "Enable RDS storage encryption. NIST SC-28 requires encryption of all data at rest. Note: encryption must be enabled at creation — snapshot and restore to an encrypted instance.",
            "doc_url": "https://csrc.nist.gov/projects/cprt/catalog#/cprt/framework/version/SP_800_53_5_1_1/home?element=SC-28",
        },
        "CCM": {
            "rule_id": "CEK-03",
            "title": "Data Encryption",
            "description": "CCM CEK-03 requires data at rest to be encrypted using industry-standard algorithms. RDS without storage encryption exposes database contents to unauthorized hardware access.",
            "recommendation": "Enable RDS encryption at rest using AWS KMS. CCM CEK-03 mandates AES-256 encryption. Use customer-managed KMS keys (CMKs) for audit trail and rotation.",
            "doc_url": "https://cloudsecurityalliance.org/research/cloud-controls-matrix",
        },
    },

    "2.3.2": {
        "NIST": {
            "rule_id": "NIST SC-7",
            "title": "Boundary Protection",
            "description": "RDS instances must not be publicly accessible. NIST SC-7 requires placing databases in private subnets behind boundary protection controls.",
            "recommendation": "Set RDS PubliclyAccessible=False. NIST SC-7 requires databases to reside in private network segments accessible only through application-tier controls.",
            "doc_url": "https://csrc.nist.gov/projects/cprt/catalog#/cprt/framework/version/SP_800_53_5_1_1/home?element=SC-7",
        },
        "CCM": {
            "rule_id": "I&S-07",
            "title": "Network Security",
            "description": "CCM I&S-07 requires network segmentation for data stores. A publicly accessible RDS instance violates the requirement to keep databases in protected network segments.",
            "recommendation": "Disable public accessibility on RDS. CCM I&S-07 requires databases to be isolated in private subnets. Access only through application-tier security groups.",
            "doc_url": "https://cloudsecurityalliance.org/research/cloud-controls-matrix",
        },
    },

    "2.2.1": {
        "NIST": {
            "rule_id": "NIST SC-28",
            "title": "Protection of Information at Rest",
            "description": "EBS volumes must be encrypted. NIST SC-28 requires cryptographic protection of data at rest for all storage volumes attached to compute instances.",
            "recommendation": "Enable EBS encryption by default in your AWS account and re-provision unencrypted volumes. NIST SC-28 requires encryption of all data at rest.",
            "doc_url": "https://csrc.nist.gov/projects/cprt/catalog#/cprt/framework/version/SP_800_53_5_1_1/home?element=SC-28",
        },
        "CCM": {
            "rule_id": "CEK-03",
            "title": "Data Encryption",
            "description": "CCM CEK-03 requires data at rest to be encrypted. EBS volumes without encryption expose stored data to unauthorized physical or logical access.",
            "recommendation": "Enable EBS encryption at account level. CCM CEK-03 mandates AES-256 encryption for all stored data. Use customer-managed KMS keys for key rotation and auditability.",
            "doc_url": "https://cloudsecurityalliance.org/research/cloud-controls-matrix",
        },
    },

    "3.2": {
        "NIST": {
            "rule_id": "NIST AU-9",
            "title": "Protection of Audit Information",
            "description": "CloudTrail log file validation must be enabled. NIST AU-9 requires protecting audit information and audit tools from unauthorized access and modification.",
            "recommendation": "Enable CloudTrail log file validation. NIST AU-9 requires integrity protection of audit logs — validation uses SHA-256 hash chains to detect tampering.",
            "doc_url": "https://csrc.nist.gov/projects/cprt/catalog#/cprt/framework/version/SP_800_53_5_1_1/home?element=AU-9",
        },
        "CCM": {
            "rule_id": "LOG-05",
            "title": "Audit Logging",
            "description": "CCM LOG-05 requires audit logs to be protected from tampering. CloudTrail log file validation ensures log integrity using cryptographic hash verification.",
            "recommendation": "Enable CloudTrail log file validation. CCM LOG-05 mandates audit log integrity protection. Validation detects any tampering with log files stored in S3.",
            "doc_url": "https://cloudsecurityalliance.org/research/cloud-controls-matrix",
        },
    },

    "3.7": {
        "NIST": {
            "rule_id": "NIST AU-9",
            "title": "Protection of Audit Information",
            "description": "CloudTrail logs must be encrypted using KMS. NIST AU-9 requires protecting audit information from unauthorized access — KMS encryption ensures log confidentiality.",
            "recommendation": "Enable KMS encryption for CloudTrail. NIST AU-9 requires protecting audit log integrity and confidentiality. Use a customer-managed KMS key with restricted key policy.",
            "doc_url": "https://csrc.nist.gov/projects/cprt/catalog#/cprt/framework/version/SP_800_53_5_1_1/home?element=AU-9",
        },
        "CCM": {
            "rule_id": "CEK-03",
            "title": "Data Encryption",
            "description": "CCM CEK-03 requires encryption of sensitive data including audit logs. CloudTrail logs without KMS encryption may expose audit trails to unauthorized access.",
            "recommendation": "Enable KMS encryption for CloudTrail. CCM CEK-03 mandates encryption of all sensitive data at rest. Use a CMK with audit-enabled key policy.",
            "doc_url": "https://cloudsecurityalliance.org/research/cloud-controls-matrix",
        },
    },

    "5.1": {
        "NIST": {
            "rule_id": "NIST SC-12",
            "title": "Cryptographic Key Establishment and Management",
            "description": "KMS keys must have automatic rotation enabled. NIST SC-12 requires cryptographic key management including key rotation to limit exposure from compromised keys.",
            "recommendation": "Enable automatic KMS key rotation. NIST SC-12 requires key rotation as part of cryptographic key management. AWS KMS rotates keys annually when enabled.",
            "doc_url": "https://csrc.nist.gov/projects/cprt/catalog#/cprt/framework/version/SP_800_53_5_1_1/home?element=SC-12",
        },
        "CCM": {
            "rule_id": "CEK-03",
            "title": "Data Encryption",
            "description": "CCM CEK-03 requires proper cryptographic key management including key rotation. KMS keys without rotation enabled may remain in use indefinitely, increasing compromise risk.",
            "recommendation": "Enable automatic KMS key rotation. CCM CEK-03 requires periodic key rotation. AWS KMS supports annual automatic rotation — enable it for all customer-managed keys.",
            "doc_url": "https://cloudsecurityalliance.org/research/cloud-controls-matrix",
        },
    },

    "1.22": {
        "NIST": {
            "rule_id": "NIST AC-6",
            "title": "Least Privilege",
            "description": "Employ the principle of least privilege. IAM policies granting full administrative access (Action:*, Resource:*) provide unrestricted access violating least-privilege requirements.",
            "recommendation": "Replace full admin policies with specific service actions. NIST AC-6 requires scoping all access to the minimum necessary. Use AWS IAM Access Analyzer to identify over-permissive policies.",
            "doc_url": "https://csrc.nist.gov/projects/cprt/catalog#/cprt/framework/version/SP_800_53_5_1_1/home?element=AC-6",
        },
        "CCM": {
            "rule_id": "IAM-01",
            "title": "Identity and Access Management Policy",
            "description": "CCM IAM-01 requires implementing least-privilege access. IAM policies with full admin access (*:*) violate the principle of minimum necessary access.",
            "recommendation": "Replace full admin policies with specific action grants. CCM IAM-01 requires periodic access reviews and least-privilege enforcement. Remove or scope down wildcard policies.",
            "doc_url": "https://cloudsecurityalliance.org/research/cloud-controls-matrix",
        },
    },

    "1.16": {
        "NIST": {
            "rule_id": "NIST AC-6",
            "title": "Least Privilege",
            "description": "IAM policies must be attached to groups or roles, not directly to users. NIST AC-6 requires managing access through role-based mechanisms for consistent least-privilege enforcement.",
            "recommendation": "Move IAM policies to groups or roles. NIST AC-6 requires organized access management — attaching policies to groups enforces consistent access control and simplifies auditing.",
            "doc_url": "https://csrc.nist.gov/projects/cprt/catalog#/cprt/framework/version/SP_800_53_5_1_1/home?element=AC-6",
        },
        "CCM": {
            "rule_id": "IAM-09",
            "title": "User Access Reviews",
            "description": "CCM IAM-09 requires periodic review of user access rights. Direct policy attachment to IAM users bypasses role-based access controls and complicates access review processes.",
            "recommendation": "Attach policies to IAM groups or roles instead of users. CCM IAM-09 requires quarterly access reviews — group-based access simplifies review and revocation.",
            "doc_url": "https://cloudsecurityalliance.org/research/cloud-controls-matrix",
        },
    },

    "4.10": {
        "NIST": {
            "rule_id": "NIST SC-7",
            "title": "Boundary Protection",
            "description": "Default security groups must not allow any inbound or outbound traffic. NIST SC-7 requires blocking all traffic in default security groups to enforce boundary protection.",
            "recommendation": "Remove all rules from default security groups. NIST SC-7 requires explicit access control — default security groups should deny all traffic to prevent accidental attachment.",
            "doc_url": "https://csrc.nist.gov/projects/cprt/catalog#/cprt/framework/version/SP_800_53_5_1_1/home?element=SC-7",
        },
        "CCM": {
            "rule_id": "I&S-07",
            "title": "Network Security",
            "description": "CCM I&S-07 requires network security controls. Default security groups with open rules represent a misconfiguration that could allow unintended traffic to reach workloads.",
            "recommendation": "Lock down default security groups by removing all rules. CCM I&S-07 mandates explicit network access controls — default groups should be empty and workloads should use dedicated security groups.",
            "doc_url": "https://cloudsecurityalliance.org/research/cloud-controls-matrix",
        },
    },

    # ── Generic ──────────────────────────────────────────────────────────────

    "GEN.1": {
        "NIST": {
            "rule_id": "NIST CM-2",
            "title": "Baseline Configuration",
            "description": "Maintain baseline configurations including asset inventory metadata. Resources without tags cannot be properly tracked in configuration management.",
            "recommendation": "Add mandatory tags (Owner, Environment, Project, CostCenter). NIST CM-2 requires maintaining system configuration documentation — tagging is the cloud-native mechanism.",
            "doc_url": "https://csrc.nist.gov/projects/cprt/catalog#/cprt/framework/version/SP_800_53_5_1_1/home?element=CM-2",
        },
        "CCM": {
            "rule_id": "GRC-01",
            "title": "Governance and Risk Management Policy",
            "description": "CCM GRC-01 requires resource governance. Untagged resources cannot be tracked for ownership, cost allocation, or security accountability.",
            "recommendation": "Apply resource tagging policy. CCM GRC-01 requires management oversight of all cloud assets — tagging enables ownership tracking, cost governance, and security posture management.",
            "doc_url": "https://cloudsecurityalliance.org/research/cloud-controls-matrix",
        },
    },
}


# ─────────────────────────────────────────────────────────────────────────────
# Translation helper
# ─────────────────────────────────────────────────────────────────────────────

def translate_finding_to_framework(finding: dict, framework: str) -> dict:
    """
    Given a finding (with cis_rule_id) and a target framework ('NIST' or 'CCM'),
    return a copy of the finding with control IDs, titles, descriptions, and
    recommendations replaced with the correct framework equivalents.

    If no mapping exists, the finding is returned with the original data and a
    framework tag added.
    """
    if framework == "CIS" or framework == "All":
        # Ensure framework field is set, return as-is
        f = dict(finding)
        f["framework"] = "CIS" if framework == "CIS" else f.get("framework", "CIS")
        f["rule_id"] = f.get("cis_rule_id") or f.get("rule_id") or f.get("check_id", "")
        return f

    # Look up the check key — try cis_rule_id, rule_id, check_id
    check_key = (
        finding.get("cis_rule_id") or
        finding.get("rule_id") or
        finding.get("check_id") or
        ""
    )

    # Try direct lookup first, then with/without "CIS " prefix as fallback
    entry = (
        FRAMEWORK_MAPPING.get(check_key) or
        FRAMEWORK_MAPPING.get(f"CIS {check_key}") or
        FRAMEWORK_MAPPING.get(check_key.replace("CIS ", "").strip()) or
        {}
    )
    mapping = entry.get(framework)

    f = dict(finding)
    f["framework"] = framework
    f["original_cis_rule_id"] = check_key  # keep original for reference

    if mapping:
        f["rule_id"] = mapping["rule_id"]
        f["cis_rule_id"] = mapping["rule_id"]  # keep field consistent
        f["rule_title"] = mapping["title"]
        f["title"] = mapping["title"]
        f["description"] = mapping["description"]
        f["recommendation"] = mapping["recommendation"]
        f["doc_url"] = mapping.get("doc_url", "")
    else:
        # No mapping found — keep original data, just tag the framework
        f["rule_id"] = check_key
        f["cis_rule_id"] = check_key

    return f


def translate_findings_to_framework(findings: list, framework: str) -> list:
    """Translate a list of findings to the target framework."""
    if not framework or framework == "All":
        return findings
    return [translate_finding_to_framework(f, framework) for f in findings]
