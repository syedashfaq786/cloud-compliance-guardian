"use client";
import { useState } from "react";
import { Icon } from "./Icons";

const COMPLIANCE_RULES = [
  // ═══════════════════════════════════════════════════════════════════════
  // CIS AWS Foundations Benchmark v3.0.0 (2024)
  // https://www.cisecurity.org/benchmark/amazon_web_services
  // ═══════════════════════════════════════════════════════════════════════

  // Section 1 — IAM
  { id: "CIS 1.4", title: "Ensure no 'root' user account access key exists", severity: "CRITICAL", category: "IAM", provider: "AWS", framework: "CIS", description: "The root user account is the most privileged user in an AWS account. AWS Access Keys allow programmatic access. Remove all access keys associated with the root account.", recommendation: "Delete root access keys via IAM console. Create individual IAM users with least-privilege policies instead. Use AWS Organizations SCPs to restrict root usage.", docUrl: "https://docs.aws.amazon.com/IAM/latest/UserGuide/best-practices.html#lock-away-credentials" },
  { id: "CIS 1.5", title: "Ensure MFA is enabled for the 'root' user account", severity: "CRITICAL", category: "IAM", provider: "AWS", framework: "CIS", description: "The root account has unrestricted access to all resources. MFA adds an extra layer of protection on top of a username and password. Enable hardware MFA for the root account.", recommendation: "Enable hardware or virtual MFA for the root account: IAM Console → Dashboard → Activate MFA on your root account.", docUrl: "https://docs.aws.amazon.com/IAM/latest/UserGuide/id_root-user.html#id_root-user_manage_mfa" },
  { id: "CIS 1.8", title: "Ensure IAM password policy requires minimum length of 14", severity: "MEDIUM", category: "IAM", provider: "AWS", framework: "CIS", description: "IAM password policy should enforce a minimum password length of at least 14 characters to prevent brute-force attacks.", recommendation: "Set minimum password length to 14 in IAM → Account settings → Password policy.", docUrl: "https://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_passwords_account-policy.html" },
  { id: "CIS 1.10", title: "Ensure MFA is enabled for all IAM users with console access", severity: "CRITICAL", category: "IAM", provider: "AWS", framework: "CIS", description: "All IAM users with AWS Management Console access must have MFA enabled. This prevents unauthorized access if passwords are compromised.", recommendation: "Enable MFA for each IAM user: IAM → Users → Security credentials → Assign MFA device. Enforce with IAM policy.", docUrl: "https://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_mfa_enable.html" },
  { id: "CIS 1.14", title: "Ensure access keys are rotated every 90 days or less", severity: "HIGH", category: "IAM", provider: "AWS", framework: "CIS", description: "Access keys should be rotated within 90 days. Old keys increase the window of opportunity for compromised credentials to be used.", recommendation: "Rotate keys: create new key → update apps → deactivate old key → delete old key. Use AWS Config rule access-keys-rotated.", docUrl: "https://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_access-keys.html#Using_RotateAccessKey" },
  { id: "CIS 1.16", title: "Ensure IAM policies are attached only to groups or roles", severity: "MEDIUM", category: "IAM", provider: "AWS", framework: "CIS", description: "IAM policies should not be attached directly to users. Attach them to groups or roles for easier management and auditing.", recommendation: "Create IAM groups, attach policies to groups, then add users to groups. Use IAM roles for service access.", docUrl: "https://docs.aws.amazon.com/IAM/latest/UserGuide/best-practices.html#use-groups-for-permissions" },
  { id: "CIS 1.22", title: "Ensure IAM policies that allow full '*:*' admin privileges are not attached", severity: "CRITICAL", category: "IAM", provider: "AWS", framework: "CIS", description: "No custom IAM policy should grant full administrative access with Action:* and Resource:*. This violates the principle of least privilege.", recommendation: "Use AWS managed policies (e.g., PowerUserAccess) instead. Scope custom policies to specific actions and resources. Use IAM Access Analyzer.", docUrl: "https://docs.aws.amazon.com/IAM/latest/UserGuide/best-practices.html#grant-least-privilege" },

  // Section 2 — Storage
  { id: "CIS 2.1.1", title: "Ensure S3 bucket policy is set to deny HTTP requests", severity: "HIGH", category: "Storage", provider: "AWS", framework: "CIS", description: "S3 bucket policies should deny any requests that are not using HTTPS (ssl). This prevents data interception during transit.", recommendation: "Add a bucket policy with Condition: {\"Bool\": {\"aws:SecureTransport\": \"false\"}} to deny non-HTTPS requests.", docUrl: "https://docs.aws.amazon.com/AmazonS3/latest/userguide/security-best-practices.html" },
  { id: "CIS 2.1.2", title: "Ensure S3 buckets have server-side encryption enabled", severity: "HIGH", category: "Storage", provider: "AWS", framework: "CIS", description: "All S3 buckets must have default server-side encryption (SSE-S3 or SSE-KMS) enabled to protect data at rest.", recommendation: "Enable default encryption: S3 → Bucket → Properties → Default encryption → Enable SSE-S3 or SSE-KMS.", docUrl: "https://docs.aws.amazon.com/AmazonS3/latest/userguide/serv-side-encryption.html" },
  { id: "CIS 2.1.4", title: "Ensure S3 public access is blocked at account and bucket level", severity: "CRITICAL", category: "Storage", provider: "AWS", framework: "CIS", description: "Block all public access to S3 buckets. Enable all four public access block settings at both account and bucket level.", recommendation: "S3 → Block Public Access settings → Enable all four options. Also set at account level in S3 settings.", docUrl: "https://docs.aws.amazon.com/AmazonS3/latest/userguide/access-control-block-public-access.html" },
  { id: "CIS 2.2.1", title: "Ensure EBS volume encryption is enabled by default", severity: "HIGH", category: "Compute", provider: "AWS", framework: "CIS", description: "EBS volumes should be encrypted at rest. Enable default EBS encryption in the EC2 settings for each region.", recommendation: "EC2 → Settings → EBS encryption → Enable 'Always encrypt new EBS volumes'. Specify a default KMS key.", docUrl: "https://docs.aws.amazon.com/ebs/latest/userguide/encryption-by-default.html" },
  { id: "CIS 2.3.1", title: "Ensure RDS instances have encryption enabled", severity: "HIGH", category: "Database", provider: "AWS", framework: "CIS", description: "RDS database instances must have storage encryption enabled at creation time using AWS KMS.", recommendation: "Enable encryption at RDS instance creation (cannot be changed after). Set storage_encrypted = true.", docUrl: "https://docs.aws.amazon.com/AmazonRDS/latest/UserGuide/Overview.Encryption.html" },
  { id: "CIS 2.3.2", title: "Ensure RDS instances are not publicly accessible", severity: "CRITICAL", category: "Database", provider: "AWS", framework: "CIS", description: "RDS instances must not be publicly accessible. They should only be reachable from within the VPC.", recommendation: "Set publicly_accessible = false. Place RDS in private subnets with security groups restricting access.", docUrl: "https://docs.aws.amazon.com/AmazonRDS/latest/UserGuide/USER_VPC.WorkingWithRDSInstanceinaVPC.html" },

  // Section 3 — Logging
  { id: "CIS 3.1", title: "Ensure CloudTrail is enabled in all regions", severity: "HIGH", category: "Logging", provider: "AWS", framework: "CIS", description: "AWS CloudTrail must be enabled and configured as a multi-region trail to log all API activity across all regions.", recommendation: "Create a trail with is_multi_region_trail = true. Send logs to a centralized S3 bucket with encryption.", docUrl: "https://docs.aws.amazon.com/awscloudtrail/latest/userguide/cloudtrail-create-and-update-a-trail.html" },
  { id: "CIS 3.2", title: "Ensure CloudTrail log file validation is enabled", severity: "MEDIUM", category: "Logging", provider: "AWS", framework: "CIS", description: "CloudTrail log file integrity validation detects whether log files were modified or deleted after delivery.", recommendation: "Enable log file validation: CloudTrail → Trail → enable_log_file_validation = true.", docUrl: "https://docs.aws.amazon.com/awscloudtrail/latest/userguide/cloudtrail-log-file-validation-intro.html" },
  { id: "CIS 3.4", title: "Ensure CloudTrail trails are integrated with CloudWatch Logs", severity: "MEDIUM", category: "Logging", provider: "AWS", framework: "CIS", description: "CloudTrail should send logs to CloudWatch Logs for real-time monitoring, alerting, and incident response.", recommendation: "Set cloud_watch_logs_group_arn and cloud_watch_logs_role_arn on the CloudTrail trail.", docUrl: "https://docs.aws.amazon.com/awscloudtrail/latest/userguide/send-cloudtrail-events-to-cloudwatch-logs.html" },
  { id: "CIS 3.7", title: "Ensure CloudTrail logs are encrypted at rest using KMS CMKs", severity: "HIGH", category: "Logging", provider: "AWS", framework: "CIS", description: "CloudTrail logs stored in S3 should be encrypted using KMS Customer Managed Keys for additional protection.", recommendation: "Set kms_key_id on CloudTrail trail configuration. Create a dedicated KMS key with appropriate key policy.", docUrl: "https://docs.aws.amazon.com/awscloudtrail/latest/userguide/encrypting-cloudtrail-log-files-with-aws-kms.html" },

  // Section 4 — Networking (CIS numbering varies; using CIS v3.0.0 section 5)
  { id: "CIS 5.1", title: "Ensure no Network ACLs allow ingress from 0.0.0.0/0 to admin ports", severity: "CRITICAL", category: "Networking", provider: "AWS", framework: "CIS", description: "Network ACLs must not allow unrestricted inbound traffic from 0.0.0.0/0 to remote admin ports (22, 3389).", recommendation: "Review VPC Network ACLs. Remove rules allowing 0.0.0.0/0 to ports 22 and 3389. Use restrictive CIDR ranges.", docUrl: "https://docs.aws.amazon.com/vpc/latest/userguide/vpc-network-acls.html" },
  { id: "CIS 5.2", title: "Ensure no security groups allow ingress from 0.0.0.0/0 to port 22", severity: "CRITICAL", category: "Networking", provider: "AWS", framework: "CIS", description: "SSH access (port 22) must not be open to the entire internet. Restrict to specific trusted CIDR ranges.", recommendation: "Restrict SSH to VPN/bastion host IPs. Consider AWS Systems Manager Session Manager as an alternative.", docUrl: "https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/security-group-rules-reference.html" },
  { id: "CIS 5.3", title: "Ensure no security groups allow ingress from 0.0.0.0/0 to port 3389", severity: "CRITICAL", category: "Networking", provider: "AWS", framework: "CIS", description: "RDP access (port 3389) must not be open to the entire internet. This is a prime target for brute-force attacks.", recommendation: "Restrict RDP to trusted IPs. Use VPN or AWS SSM Fleet Manager for remote Windows access.", docUrl: "https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/security-group-rules-reference.html" },
  { id: "CIS 5.4", title: "Ensure no security groups allow unrestricted ingress to database ports", severity: "HIGH", category: "Networking", provider: "AWS", framework: "CIS", description: "Security groups must not allow unrestricted 0.0.0.0/0 access to database ports (3306, 5432, 1433, 27017).", recommendation: "Restrict database ports to application-tier security groups only. Never expose databases to the internet.", docUrl: "https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/security-group-rules-reference.html" },
  { id: "CIS 5.6", title: "Ensure VPC flow logging is enabled in all VPCs", severity: "MEDIUM", category: "Networking", provider: "AWS", framework: "CIS", description: "VPC Flow Logs capture IP traffic information for network interfaces in your VPC for security monitoring.", recommendation: "Enable VPC Flow Logs for each VPC. Send to CloudWatch Logs or S3 with traffic_type = ALL.", docUrl: "https://docs.aws.amazon.com/vpc/latest/userguide/flow-logs.html" },

  // Section — Encryption
  { id: "CIS 3.8", title: "Ensure KMS key rotation is enabled", severity: "MEDIUM", category: "Encryption", provider: "AWS", framework: "CIS", description: "AWS KMS Customer Master Keys should have automatic annual key rotation enabled to limit blast radius.", recommendation: "Enable rotation: KMS → Customer managed keys → Key → Key rotation → Enable automatic rotation.", docUrl: "https://docs.aws.amazon.com/kms/latest/developerguide/rotate-keys.html" },

  // ═══════════════════════════════════════════════════════════════════════
  // CIS Microsoft Azure Foundations Benchmark v2.1.0 (2024)
  // https://www.cisecurity.org/benchmark/azure
  // ═══════════════════════════════════════════════════════════════════════

  { id: "CIS-AZ 1.1.1", title: "Ensure Security Defaults are enabled on Azure AD", severity: "HIGH", category: "IAM", provider: "Azure", framework: "CIS", description: "Security Defaults enforce MFA registration, block legacy authentication, and require MFA for admin actions.", recommendation: "Azure AD → Properties → Manage Security defaults → Enable. Or use Conditional Access for more control.", docUrl: "https://learn.microsoft.com/en-us/entra/fundamentals/security-defaults" },
  { id: "CIS-AZ 1.2.1", title: "Ensure MFA is enabled for all users in administrative roles", severity: "CRITICAL", category: "IAM", provider: "Azure", framework: "CIS", description: "All users with administrative roles (Global Admin, Security Admin, etc.) must have MFA enabled.", recommendation: "Use Conditional Access policies to require MFA for all admin role assignments.", docUrl: "https://learn.microsoft.com/en-us/entra/identity/authentication/howto-mfa-userstates" },
  { id: "CIS-AZ 3.1", title: "Ensure Storage account uses HTTPS-only traffic", severity: "HIGH", category: "Storage", provider: "Azure", framework: "CIS", description: "Storage accounts must enforce HTTPS to prevent data interception via unencrypted HTTP connections.", recommendation: "Set supportsHttpsTrafficOnly = true on all storage accounts.", docUrl: "https://learn.microsoft.com/en-us/azure/storage/common/storage-require-secure-transfer" },
  { id: "CIS-AZ 3.2", title: "Ensure Storage account access keys are periodically rotated", severity: "MEDIUM", category: "Storage", provider: "Azure", framework: "CIS", description: "Storage account access keys should be rotated regularly (every 90 days) to limit exposure window.", recommendation: "Use Azure Key Vault for managed key rotation. Set up key expiration policies.", docUrl: "https://learn.microsoft.com/en-us/azure/storage/common/storage-account-keys-manage" },
  { id: "CIS-AZ 4.1.1", title: "Ensure Azure SQL Database has auditing enabled", severity: "HIGH", category: "Database", provider: "Azure", framework: "CIS", description: "SQL Database auditing tracks database events and writes them to an audit log in Azure Storage or Log Analytics.", recommendation: "Enable auditing: SQL Server → Auditing → Enable → Configure storage account or Log Analytics.", docUrl: "https://learn.microsoft.com/en-us/azure/azure-sql/database/auditing-overview" },
  { id: "CIS-AZ 4.2.1", title: "Ensure Azure SQL Database uses TDE encryption", severity: "CRITICAL", category: "Database", provider: "Azure", framework: "CIS", description: "Transparent Data Encryption (TDE) encrypts SQL Database, Managed Instance, and Synapse data at rest.", recommendation: "TDE is enabled by default. Verify via Portal: SQL Database → Transparent data encryption → Status: Enabled.", docUrl: "https://learn.microsoft.com/en-us/azure/azure-sql/database/transparent-data-encryption-tde-overview" },
  { id: "CIS-AZ 6.1", title: "Ensure NSG does not allow SSH from the internet", severity: "CRITICAL", category: "Networking", provider: "Azure", framework: "CIS", description: "Network Security Groups must not allow inbound SSH (port 22) from any source (* or 0.0.0.0/0).", recommendation: "Restrict SSH source to specific IPs. Use Azure Bastion for secure SSH/RDP access.", docUrl: "https://learn.microsoft.com/en-us/azure/virtual-network/network-security-groups-overview" },
  { id: "CIS-AZ 6.2", title: "Ensure NSG does not allow RDP from the internet", severity: "CRITICAL", category: "Networking", provider: "Azure", framework: "CIS", description: "Network Security Groups must not allow inbound RDP (port 3389) from the internet.", recommendation: "Use Azure Bastion or VPN Gateway for RDP access. Never expose RDP directly to the internet.", docUrl: "https://learn.microsoft.com/en-us/azure/bastion/bastion-overview" },
  { id: "CIS-AZ 8.1", title: "Ensure Azure Key Vault has soft delete enabled", severity: "HIGH", category: "Encryption", provider: "Azure", framework: "CIS", description: "Key Vault soft delete allows recovery of deleted vaults and secrets during a retention period (7-90 days).", recommendation: "Set soft_delete_retention_days >= 7. Soft delete is now enabled by default for new Key Vaults.", docUrl: "https://learn.microsoft.com/en-us/azure/key-vault/general/soft-delete-overview" },
  { id: "CIS-AZ 8.2", title: "Ensure Azure Key Vault has purge protection enabled", severity: "HIGH", category: "Encryption", provider: "Azure", framework: "CIS", description: "Purge protection prevents permanent deletion of key vaults and secrets during the soft delete retention period.", recommendation: "Enable purge protection: Key Vault → Properties → Enable purge protection.", docUrl: "https://learn.microsoft.com/en-us/azure/key-vault/general/soft-delete-overview#purge-protection" },
  { id: "CIS-AZ 5.1.1", title: "Ensure Activity Log alerts exist for critical operations", severity: "MEDIUM", category: "Logging", provider: "Azure", framework: "CIS", description: "Activity Log alerts should monitor critical operations like policy assignments, security group changes, and key vault access.", recommendation: "Create Activity Log alerts for: Create/Update Policy Assignment, Create/Delete Security Solution.", docUrl: "https://learn.microsoft.com/en-us/azure/azure-monitor/alerts/activity-log-alerts" },
  { id: "CIS-AZ 7.1", title: "Ensure VM disks are encrypted with ADE or SSE with CMK", severity: "HIGH", category: "Compute", provider: "Azure", framework: "CIS", description: "Virtual Machine OS and data disks must be encrypted using Azure Disk Encryption or Server-Side Encryption with customer-managed keys.", recommendation: "Use Azure Disk Encryption (ADE) with Key Vault or enable SSE with customer-managed keys.", docUrl: "https://learn.microsoft.com/en-us/azure/virtual-machines/disk-encryption-overview" },

  // ═══════════════════════════════════════════════════════════════════════
  // CIS Google Cloud Platform Benchmark v2.0.0 (2023)
  // https://www.cisecurity.org/benchmark/google_cloud_computing_platform
  // ═══════════════════════════════════════════════════════════════════════

  { id: "CIS-GCP 1.1", title: "Ensure corporate login credentials are used instead of Gmail", severity: "HIGH", category: "IAM", provider: "GCP", framework: "CIS", description: "GCP projects should use corporate Google Workspace or Cloud Identity accounts, not personal Gmail accounts.", recommendation: "Use Cloud Identity or Google Workspace managed accounts for all GCP access.", docUrl: "https://cloud.google.com/docs/enterprise/best-practices-for-enterprise-organizations#identity" },
  { id: "CIS-GCP 1.4", title: "Ensure service account keys are rotated within 90 days", severity: "HIGH", category: "IAM", provider: "GCP", framework: "CIS", description: "Service account keys should be rotated every 90 days or less. Old keys increase risk of unauthorized access.", recommendation: "Delete keys older than 90 days. Prefer Workload Identity or attached service accounts over key-based auth.", docUrl: "https://cloud.google.com/iam/docs/best-practices-for-managing-service-account-keys" },
  { id: "CIS-GCP 2.1", title: "Ensure Cloud Audit Logging is enabled for all services", severity: "HIGH", category: "Logging", provider: "GCP", framework: "CIS", description: "Cloud Audit Logs should capture Admin Activity, Data Access, and System Event logs for all GCP services.", recommendation: "Configure audit log policy at org/project level for allServices with all log types enabled.", docUrl: "https://cloud.google.com/logging/docs/audit/configure-data-access" },
  { id: "CIS-GCP 3.1", title: "Ensure VPC firewall rules do not allow SSH from 0.0.0.0/0", severity: "CRITICAL", category: "Networking", provider: "GCP", framework: "CIS", description: "Firewall rules must not allow SSH (port 22) ingress from all sources (0.0.0.0/0).", recommendation: "Restrict source_ranges to specific CIDRs. Use Identity-Aware Proxy (IAP) tunneling for SSH.", docUrl: "https://cloud.google.com/iap/docs/using-tcp-forwarding" },
  { id: "CIS-GCP 3.2", title: "Ensure VPC firewall rules do not allow RDP from 0.0.0.0/0", severity: "CRITICAL", category: "Networking", provider: "GCP", framework: "CIS", description: "Firewall rules must not allow RDP (port 3389) ingress from all sources.", recommendation: "Use Identity-Aware Proxy (IAP) for RDP access instead of public firewall rules.", docUrl: "https://cloud.google.com/iap/docs/using-tcp-forwarding" },
  { id: "CIS-GCP 4.1", title: "Ensure GCE instances do not use default service account", severity: "HIGH", category: "Compute", provider: "GCP", framework: "CIS", description: "Default Compute Engine service accounts have the Editor role, granting overly broad permissions to instances.", recommendation: "Create dedicated service accounts with minimal permissions for each workload/application.", docUrl: "https://cloud.google.com/compute/docs/access/service-accounts#default_service_account" },
  { id: "CIS-GCP 4.6", title: "Ensure Compute instances do not have public IP addresses", severity: "HIGH", category: "Compute", provider: "GCP", framework: "CIS", description: "Instances should use private IPs only. Use Cloud NAT for outbound internet access.", recommendation: "Remove access_config from network_interface. Use Cloud NAT for egress traffic.", docUrl: "https://cloud.google.com/nat/docs/overview" },
  { id: "CIS-GCP 5.1", title: "Ensure GCS buckets are not anonymously or publicly accessible", severity: "CRITICAL", category: "Storage", provider: "GCP", framework: "CIS", description: "Cloud Storage buckets must not grant access to allUsers or allAuthenticatedUsers IAM members.", recommendation: "Remove allUsers/allAuthenticatedUsers bindings. Enable uniform bucket-level access.", docUrl: "https://cloud.google.com/storage/docs/using-public-access-prevention" },
  { id: "CIS-GCP 5.2", title: "Ensure GCS buckets have uniform bucket-level access enabled", severity: "HIGH", category: "Storage", provider: "GCP", framework: "CIS", description: "Uniform access disables ACLs and ensures all access is managed through IAM policies only.", recommendation: "Enable uniform bucket-level access in bucket settings. Migrate from ACLs to IAM.", docUrl: "https://cloud.google.com/storage/docs/uniform-bucket-level-access" },
  { id: "CIS-GCP 6.1", title: "Ensure Cloud SQL instances are not publicly accessible", severity: "CRITICAL", category: "Database", provider: "GCP", framework: "CIS", description: "Cloud SQL instances should not have authorized networks allowing 0.0.0.0/0.", recommendation: "Remove 0.0.0.0/0 from authorized_networks. Use Cloud SQL Auth Proxy for connections.", docUrl: "https://cloud.google.com/sql/docs/mysql/connect-auth-proxy" },
  { id: "CIS-GCP 6.7", title: "Ensure Cloud SQL instances have automated backups", severity: "HIGH", category: "Database", provider: "GCP", framework: "CIS", description: "Automated backups ensure point-in-time recovery for Cloud SQL databases.", recommendation: "Enable automated backups with point_in_time_recovery_enabled = true.", docUrl: "https://cloud.google.com/sql/docs/mysql/backup-recovery/backups" },
  { id: "CIS-GCP 7.1", title: "Ensure Cloud KMS keys have rotation configured", severity: "MEDIUM", category: "Encryption", provider: "GCP", framework: "CIS", description: "KMS key rotation should be configured with a period of no more than 90 days.", recommendation: "Set rotation_period = 7776000s (90 days) on google_kms_crypto_key resources.", docUrl: "https://cloud.google.com/kms/docs/key-rotation" },

  // ═══════════════════════════════════════════════════════════════════════
  // NIST 800-53 Rev 5 — Security and Privacy Controls
  // https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final
  // ═══════════════════════════════════════════════════════════════════════

  // Access Control (AC)
  { id: "NIST AC-2", title: "Account Management", severity: "HIGH", category: "IAM", provider: "All", framework: "NIST", description: "Define and manage information system accounts including identifying account types, group memberships, access authorizations, and establishing conditions for account usage.", recommendation: "Implement automated account management. Disable inactive accounts after 30 days. Review accounts quarterly. Use IAM roles with time-limited sessions.", docUrl: "https://csrc.nist.gov/projects/cprt/catalog#/cprt/framework/version/SP_800_53_5_1_1/home?element=AC-2" },
  { id: "NIST AC-3", title: "Access Enforcement", severity: "CRITICAL", category: "IAM", provider: "All", framework: "NIST", description: "The system must enforce approved authorizations for logical access to information and system resources in accordance with applicable access control policies.", recommendation: "Implement RBAC or ABAC. Use IAM policies with least privilege. Deny by default, allow by exception. Audit access enforcement logs.", docUrl: "https://csrc.nist.gov/projects/cprt/catalog#/cprt/framework/version/SP_800_53_5_1_1/home?element=AC-3" },
  { id: "NIST AC-6", title: "Least Privilege", severity: "CRITICAL", category: "IAM", provider: "All", framework: "NIST", description: "Employ the principle of least privilege, allowing only authorized access that is necessary for users and processes to accomplish assigned tasks.", recommendation: "Scope IAM policies to specific actions/resources. Use AWS IAM Access Analyzer, Azure PIM, or GCP IAM Recommender. Review permissions quarterly.", docUrl: "https://csrc.nist.gov/projects/cprt/catalog#/cprt/framework/version/SP_800_53_5_1_1/home?element=AC-6" },
  { id: "NIST AC-17", title: "Remote Access", severity: "HIGH", category: "Networking", provider: "All", framework: "NIST", description: "Establish usage restrictions, configuration requirements, and connection requirements for each type of remote access allowed.", recommendation: "Use VPN or SSM Session Manager for remote access. Enforce MFA. Restrict SSH/RDP to bastion hosts. Log all remote sessions.", docUrl: "https://csrc.nist.gov/projects/cprt/catalog#/cprt/framework/version/SP_800_53_5_1_1/home?element=AC-17" },

  // Audit & Accountability (AU)
  { id: "NIST AU-2", title: "Event Logging", severity: "HIGH", category: "Logging", provider: "All", framework: "NIST", description: "Identify events that the system must be capable of logging in support of the audit function: account management, access, privilege use, and policy changes.", recommendation: "Enable CloudTrail (AWS), Activity Log (Azure), or Cloud Audit Logs (GCP). Log authentication, authorization, and admin events.", docUrl: "https://csrc.nist.gov/projects/cprt/catalog#/cprt/framework/version/SP_800_53_5_1_1/home?element=AU-2" },
  { id: "NIST AU-3", title: "Content of Audit Records", severity: "MEDIUM", category: "Logging", provider: "All", framework: "NIST", description: "Audit records must contain what type of event occurred, when and where it occurred, the source, the outcome, and the identity of subjects/objects involved.", recommendation: "Configure log enrichment with VPC Flow Logs, DNS logs, and application-level logging. Ensure timestamps use UTC.", docUrl: "https://csrc.nist.gov/projects/cprt/catalog#/cprt/framework/version/SP_800_53_5_1_1/home?element=AU-3" },
  { id: "NIST AU-6", title: "Audit Record Review, Analysis, and Reporting", severity: "MEDIUM", category: "Logging", provider: "All", framework: "NIST", description: "Review and analyze system audit records for indications of inappropriate or unusual activity. Report findings to designated officials.", recommendation: "Use AWS GuardDuty, Azure Sentinel, or GCP Security Command Center for automated analysis and alerting.", docUrl: "https://csrc.nist.gov/projects/cprt/catalog#/cprt/framework/version/SP_800_53_5_1_1/home?element=AU-6" },
  { id: "NIST AU-9", title: "Protection of Audit Information", severity: "HIGH", category: "Logging", provider: "All", framework: "NIST", description: "Protect audit information and audit logging tools from unauthorized access, modification, and deletion.", recommendation: "Encrypt audit logs with KMS. Enable log file validation. Store in immutable storage (S3 Object Lock, WORM). Restrict log bucket access.", docUrl: "https://csrc.nist.gov/projects/cprt/catalog#/cprt/framework/version/SP_800_53_5_1_1/home?element=AU-9" },

  // Identification & Authentication (IA)
  { id: "NIST IA-2", title: "Identification and Authentication (Organizational Users)", severity: "CRITICAL", category: "IAM", provider: "All", framework: "NIST", description: "Uniquely identify and authenticate organizational users. Implement multi-factor authentication for privileged and non-privileged accounts.", recommendation: "Enforce MFA for all users. Use hardware security keys for privileged accounts. Integrate with corporate IdP via SAML/OIDC.", docUrl: "https://csrc.nist.gov/projects/cprt/catalog#/cprt/framework/version/SP_800_53_5_1_1/home?element=IA-2" },
  { id: "NIST IA-5", title: "Authenticator Management", severity: "HIGH", category: "IAM", provider: "All", framework: "NIST", description: "Manage system authenticators (passwords, tokens, PKI, biometrics) by establishing initial content, maintenance, and protection.", recommendation: "Enforce password complexity (min 14 chars). Rotate access keys every 90 days. Use secrets managers for API keys.", docUrl: "https://csrc.nist.gov/projects/cprt/catalog#/cprt/framework/version/SP_800_53_5_1_1/home?element=IA-5" },

  // System and Communications Protection (SC)
  { id: "NIST SC-7", title: "Boundary Protection", severity: "CRITICAL", category: "Networking", provider: "All", framework: "NIST", description: "Monitor and control communications at external and key internal boundaries. Implement subnetworks for publicly accessible system components.", recommendation: "Use public/private subnets. Deploy WAF and NACLs. Restrict security groups to minimum ports. Enable VPC Flow Logs.", docUrl: "https://csrc.nist.gov/projects/cprt/catalog#/cprt/framework/version/SP_800_53_5_1_1/home?element=SC-7" },
  { id: "NIST SC-8", title: "Transmission Confidentiality and Integrity", severity: "HIGH", category: "Encryption", provider: "All", framework: "NIST", description: "Protect the confidentiality and integrity of transmitted information using cryptographic mechanisms.", recommendation: "Enforce TLS 1.2+ for all connections. Use HTTPS-only on S3, enforce SSL on RDS. Use VPN for private connectivity.", docUrl: "https://csrc.nist.gov/projects/cprt/catalog#/cprt/framework/version/SP_800_53_5_1_1/home?element=SC-8" },
  { id: "NIST SC-12", title: "Cryptographic Key Establishment and Management", severity: "HIGH", category: "Encryption", provider: "All", framework: "NIST", description: "Establish and manage cryptographic keys when cryptography is employed. Use approved key management technology and processes.", recommendation: "Use AWS KMS, Azure Key Vault, or GCP Cloud KMS. Enable automatic key rotation. Use separate keys per environment.", docUrl: "https://csrc.nist.gov/projects/cprt/catalog#/cprt/framework/version/SP_800_53_5_1_1/home?element=SC-12" },
  { id: "NIST SC-28", title: "Protection of Information at Rest", severity: "HIGH", category: "Encryption", provider: "All", framework: "NIST", description: "Protect the confidentiality and integrity of information at rest using cryptographic mechanisms.", recommendation: "Enable encryption on all storage: S3/EBS/RDS (AWS), Storage/Disk/SQL (Azure), GCS/Persistent Disk/Cloud SQL (GCP).", docUrl: "https://csrc.nist.gov/projects/cprt/catalog#/cprt/framework/version/SP_800_53_5_1_1/home?element=SC-28" },

  // Configuration Management (CM)
  { id: "NIST CM-2", title: "Baseline Configuration", severity: "MEDIUM", category: "Compute", provider: "All", framework: "NIST", description: "Develop, document, and maintain baseline configurations for information systems under configuration control.", recommendation: "Use AWS Config, Azure Policy, or GCP Organization Policy. Define baseline images (AMI/VM Image). Use Infrastructure as Code.", docUrl: "https://csrc.nist.gov/projects/cprt/catalog#/cprt/framework/version/SP_800_53_5_1_1/home?element=CM-2" },
  { id: "NIST CM-6", title: "Configuration Settings", severity: "MEDIUM", category: "Compute", provider: "All", framework: "NIST", description: "Establish mandatory configuration settings for IT products used in the system using security configuration checklists.", recommendation: "Apply CIS Benchmarks as baseline configurations. Use AWS Systems Manager, Azure Automation, or GCP OS Config.", docUrl: "https://csrc.nist.gov/projects/cprt/catalog#/cprt/framework/version/SP_800_53_5_1_1/home?element=CM-6" },

  // Contingency Planning (CP)
  { id: "NIST CP-9", title: "System Backup", severity: "HIGH", category: "Database", provider: "All", framework: "NIST", description: "Conduct backups of system-level and user-level information. Protect backup confidentiality, integrity, and availability.", recommendation: "Enable automated backups for RDS/SQL/Cloud SQL. Set retention >= 7 days. Test restore procedures quarterly. Encrypt backups.", docUrl: "https://csrc.nist.gov/projects/cprt/catalog#/cprt/framework/version/SP_800_53_5_1_1/home?element=CP-9" },
];

const FRAMEWORKS = ["All", "CIS", "NIST"];
const PROVIDERS = ["All", "AWS", "Azure", "GCP"];
const CATEGORIES = ["All", ...Array.from(new Set(COMPLIANCE_RULES.map((r) => r.category))).sort()];
const SEVERITIES = ["All", "CRITICAL", "HIGH", "MEDIUM", "LOW"];

const PROVIDER_COLORS = {
  AWS: { bg: "rgba(255,153,0,0.08)", color: "#ff9900", border: "rgba(255,153,0,0.2)" },
  Azure: { bg: "rgba(0,120,212,0.08)", color: "#0078d4", border: "rgba(0,120,212,0.2)" },
  GCP: { bg: "rgba(66,133,244,0.08)", color: "#4285f4", border: "rgba(66,133,244,0.2)" },
  All: { bg: "rgba(139,92,246,0.08)", color: "#8b5cf6", border: "rgba(139,92,246,0.2)" },
};

const FRAMEWORK_COLORS = {
  CIS: { bg: "rgba(34,197,94,0.08)", color: "#16a34a", border: "rgba(34,197,94,0.2)" },
  NIST: { bg: "rgba(59,130,246,0.08)", color: "#2563eb", border: "rgba(59,130,246,0.2)" },
};

export default function CISRulesView() {
  const [searchQuery, setSearchQuery] = useState("");
  const [categoryFilter, setCategoryFilter] = useState("All");
  const [severityFilter, setSeverityFilter] = useState("All");
  const [providerFilter, setProviderFilter] = useState("All");
  const [frameworkFilter, setFrameworkFilter] = useState("All");
  const [expandedRule, setExpandedRule] = useState(null);

  const filtered = COMPLIANCE_RULES.filter((r) => {
    const q = searchQuery.toLowerCase();
    const matchesSearch = !searchQuery ||
      r.title.toLowerCase().includes(q) ||
      r.id.toLowerCase().includes(q) ||
      r.description.toLowerCase().includes(q) ||
      r.category.toLowerCase().includes(q) ||
      r.provider.toLowerCase().includes(q) ||
      r.framework.toLowerCase().includes(q) ||
      r.recommendation.toLowerCase().includes(q);
    const matchesCategory = categoryFilter === "All" || r.category === categoryFilter;
    const matchesSeverity = severityFilter === "All" || r.severity === severityFilter;
    const matchesProvider = providerFilter === "All" || r.provider === providerFilter;
    const matchesFramework = frameworkFilter === "All" || r.framework === frameworkFilter;
    return matchesSearch && matchesCategory && matchesSeverity && matchesProvider && matchesFramework;
  });

  const frameworkCounts = {
    All: COMPLIANCE_RULES.length,
    CIS: COMPLIANCE_RULES.filter(r => r.framework === "CIS").length,
    NIST: COMPLIANCE_RULES.filter(r => r.framework === "NIST").length,
  };

  const providerCounts = {
    All: filtered.length,
    AWS: filtered.filter(r => r.provider === "AWS").length,
    Azure: filtered.filter(r => r.provider === "Azure").length,
    GCP: filtered.filter(r => r.provider === "GCP").length,
  };

  return (
    <div>
      <div className="page-header">
        <h2>Compliance Rules</h2>
        <p>Reference catalog of CIS Benchmark and NIST 800-53 compliance rules across AWS, Azure, and GCP</p>
      </div>

      {/* ── Framework Tabs ─────────────────────────────────────────── */}
      <div style={{ display: "flex", gap: 10, marginBottom: 12 }}>
        {FRAMEWORKS.map((f) => (
          <button
            key={f}
            className={`period-btn ${frameworkFilter === f ? "active" : ""}`}
            onClick={() => setFrameworkFilter(f)}
            style={{ display: "flex", alignItems: "center", gap: 6, fontWeight: 600 }}
          >
            {f === "CIS" && <Icon name="shield" size={14} />}
            {f === "NIST" && <Icon name="clipboard" size={14} />}
            {f} <span style={{ opacity: 0.7, fontSize: 11 }}>({frameworkCounts[f]})</span>
          </button>
        ))}
      </div>

      {/* ── Provider Tabs ──────────────────────────────────────────── */}
      <div style={{ display: "flex", gap: 10, marginBottom: 16 }}>
        {PROVIDERS.map((p) => (
          <button
            key={p}
            className={`period-btn ${providerFilter === p ? "active" : ""}`}
            onClick={() => setProviderFilter(p)}
            style={{ display: "flex", alignItems: "center", gap: 6 }}
          >
            {p !== "All" && (
              <img src={`/logos/${p.toLowerCase()}.svg`} alt={p} style={{ width: 16, height: 16 }} />
            )}
            {p} <span style={{ opacity: 0.7, fontSize: 11 }}>({providerCounts[p]})</span>
          </button>
        ))}
      </div>

      {/* ── Search & Filters ───────────────────────────────────────── */}
      <div className="glass-card" style={{ marginBottom: 20 }}>
        <div className="card-body" style={{ display: "flex", gap: 12, flexWrap: "wrap", alignItems: "center" }}>
          <div className="input-wrapper" style={{ flex: 1, minWidth: 200 }}>
            <span className="input-icon"><Icon name="search" size={16} /></span>
            <input
              type="text"
              placeholder="Search by rule ID, title, description, framework..."
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
              style={{ width: "100%" }}
            />
          </div>
          <select className="filter-select" value={categoryFilter} onChange={(e) => setCategoryFilter(e.target.value)}>
            {CATEGORIES.map((c) => <option key={c} value={c}>{c === "All" ? "All Categories" : c}</option>)}
          </select>
          <select className="filter-select" value={severityFilter} onChange={(e) => setSeverityFilter(e.target.value)}>
            {SEVERITIES.map((s) => <option key={s} value={s}>{s === "All" ? "All Severities" : s}</option>)}
          </select>
          {searchQuery && (
            <button
              onClick={() => setSearchQuery("")}
              style={{
                padding: "8px 14px", border: "1px solid var(--border-glass)", borderRadius: "var(--radius-sm)",
                background: "var(--bg-card)", color: "var(--text-muted)", fontSize: 12, fontWeight: 600,
                cursor: "pointer", fontFamily: "'Inter', sans-serif"
              }}
            >
              Clear
            </button>
          )}
        </div>
      </div>

      {/* ── Results Count ──────────────────────────────────────────── */}
      <p style={{ fontSize: 13, color: "var(--text-muted)", marginBottom: 16 }}>
        Showing {filtered.length} of {COMPLIANCE_RULES.length} rules
        {searchQuery && <> matching &quot;<strong style={{ color: "var(--text-primary)" }}>{searchQuery}</strong>&quot;</>}
      </p>

      {/* ── Rules Grid ─────────────────────────────────────────────── */}
      <div className="rules-grid">
        {filtered.map((rule) => {
          const pc = PROVIDER_COLORS[rule.provider] || PROVIDER_COLORS.All;
          const fc = FRAMEWORK_COLORS[rule.framework] || FRAMEWORK_COLORS.CIS;
          const isExpanded = expandedRule === rule.id;
          return (
            <div key={rule.id} className="glass-card rule-card" onClick={() => setExpandedRule(isExpanded ? null : rule.id)}
              style={{ cursor: "pointer" }}>
              <div className="card-body">
                <div style={{ display: "flex", justifyContent: "space-between", alignItems: "flex-start", marginBottom: 10 }}>
                  <div style={{ display: "flex", alignItems: "center", gap: 6, flexWrap: "wrap" }}>
                    <span className="rule-id" style={{ fontSize: 13 }}>{rule.id}</span>
                    <span style={{
                      fontSize: 9, fontWeight: 700, padding: "2px 6px", borderRadius: 99,
                      background: fc.bg, color: fc.color, border: `1px solid ${fc.border}`,
                      textTransform: "uppercase", letterSpacing: 0.5,
                    }}>{rule.framework}</span>
                    <span style={{
                      fontSize: 9, fontWeight: 700, padding: "2px 6px", borderRadius: 99,
                      background: pc.bg, color: pc.color, border: `1px solid ${pc.border}`
                    }}>{rule.provider}</span>
                  </div>
                  <span className={`severity-badge ${rule.severity.toLowerCase()}`}>{rule.severity}</span>
                </div>
                <h4 style={{ fontSize: 14, fontWeight: 600, marginBottom: 8, lineHeight: 1.4 }}>{rule.title}</h4>
                <p style={{ fontSize: 12, color: "var(--text-secondary)", lineHeight: 1.5, marginBottom: 10 }}>{rule.description}</p>

                {/* Expanded Recommendation + Link */}
                {isExpanded && (
                  <div className="animate-fade-in" style={{ marginTop: 12 }}>
                    <div style={{ padding: "12px 14px", background: "rgba(255,122,0,0.04)", borderRadius: 10, border: "1px solid rgba(255,122,0,0.1)", marginBottom: 10 }}>
                      <p style={{ fontSize: 11, fontWeight: 700, color: "var(--accent-amber)", marginBottom: 4 }}>
                        <Icon name="circle-check" size={12} style={{ marginRight: 4 }} /> Recommendation
                      </p>
                      <p style={{ fontSize: 12, color: "var(--text-secondary)", lineHeight: 1.6 }}>{rule.recommendation}</p>
                    </div>
                    {rule.docUrl && (
                      <a
                        href={rule.docUrl}
                        target="_blank"
                        rel="noopener noreferrer"
                        onClick={(e) => e.stopPropagation()}
                        style={{
                          display: "inline-flex", alignItems: "center", gap: 6,
                          fontSize: 12, fontWeight: 600, color: "var(--accent-primary)",
                          textDecoration: "none", padding: "6px 12px", borderRadius: 6,
                          background: "rgba(255,122,0,0.06)", border: "1px solid rgba(255,122,0,0.15)",
                          transition: "all 0.2s",
                        }}
                        onMouseEnter={(e) => e.target.style.background = "rgba(255,122,0,0.12)"}
                        onMouseLeave={(e) => e.target.style.background = "rgba(255,122,0,0.06)"}
                      >
                        <Icon name="arrow-up" size={12} style={{ transform: "rotate(45deg)" }} />
                        View Official Documentation
                      </a>
                    )}
                  </div>
                )}

                <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", marginTop: 10 }}>
                  <span className="category-tag">{rule.category}</span>
                  <span style={{ fontSize: 11, color: "var(--text-muted)" }}>
                    {isExpanded ? "Click to collapse" : "Click for details"}
                  </span>
                </div>
              </div>
            </div>
          );
        })}
      </div>

      {filtered.length === 0 && (
        <div className="glass-card" style={{ padding: 48, textAlign: "center" }}>
          <Icon name="search" size={40} style={{ color: "var(--text-muted)", marginBottom: 12 }} />
          <h3 style={{ fontSize: 16, color: "var(--text-secondary)" }}>No rules match your filters</h3>
          <p style={{ color: "var(--text-muted)", fontSize: 13 }}>Try adjusting your search or filter criteria.</p>
        </div>
      )}
    </div>
  );
}
