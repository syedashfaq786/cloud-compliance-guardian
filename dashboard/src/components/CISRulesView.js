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

  // ═══════════════════════════════════════════════════════════════════════
  // CSA Cloud Controls Matrix (CCM) v4.1
  // https://cloudsecurityalliance.org/research/cloud-controls-matrix
  // 17 Domains · 207 Controls · Applicable to AWS, Azure, GCP and all clouds
  // ═══════════════════════════════════════════════════════════════════════

  // A&A — Audit & Assurance
  { id: "A&A-01", title: "Audit and Assurance Policy and Procedures", severity: "MEDIUM", category: "Logging", provider: "All", framework: "CCM", description: "Establish, document, approve, communicate, and maintain an audit and assurance policy with procedures. Review and update at least annually.", recommendation: "Create a formal audit policy document. Schedule annual reviews. Assign an audit owner. Include scope, frequency, and escalation paths.", docUrl: "https://cloudsecurityalliance.org/research/cloud-controls-matrix" },
  { id: "A&A-02", title: "Independent Audits", severity: "HIGH", category: "Logging", provider: "All", framework: "CCM", description: "Independent reviews and assessments of the cloud service must be conducted at least annually to ensure risk and compliance objectives are met.", recommendation: "Engage third-party auditors for SOC 2, ISO 27001, or CSA STAR assessments. Share reports with customers via CCM CAIQ.", docUrl: "https://cloudsecurityalliance.org/research/cloud-controls-matrix" },
  { id: "A&A-05", title: "Audit Management Process", severity: "MEDIUM", category: "Logging", provider: "All", framework: "CCM", description: "Define and implement an audit management process to identify audit requirements, schedule audits, conduct audits, and track findings to remediation.", recommendation: "Use a GRC tool (e.g., ServiceNow GRC, Archer) to track audit findings. Assign remediation owners with deadlines.", docUrl: "https://cloudsecurityalliance.org/research/cloud-controls-matrix" },

  // AIS — Application & Interface Security
  { id: "AIS-01", title: "Application and Interface Security Policy", severity: "MEDIUM", category: "Compute", provider: "All", framework: "CCM", description: "Establish a policy for application and interface security covering design, development, acquisition, testing, and deployment of applications.", recommendation: "Adopt OWASP SAMM or BSIMM as a secure development framework. Integrate SAST/DAST into CI/CD pipelines.", docUrl: "https://cloudsecurityalliance.org/research/cloud-controls-matrix" },
  { id: "AIS-04", title: "Application Security Testing", severity: "HIGH", category: "Compute", provider: "All", framework: "CCM", description: "Perform application security testing (SAST, DAST, penetration testing) throughout the software development lifecycle for all customer-facing applications.", recommendation: "Integrate Snyk, SonarQube, or Checkmarx into CI/CD. Conduct annual penetration tests by qualified third parties.", docUrl: "https://cloudsecurityalliance.org/research/cloud-controls-matrix" },

  // BCR — Business Continuity Management & Operational Resilience
  { id: "BCR-01", title: "Business Continuity Planning", severity: "HIGH", category: "Database", provider: "All", framework: "CCM", description: "Establish, document, approve, and maintain a business continuity plan (BCP) to ensure availability of critical services during disruptions.", recommendation: "Define RTO/RPO targets. Test BCP annually via tabletop exercises. Store BCP in an accessible, version-controlled location.", docUrl: "https://cloudsecurityalliance.org/research/cloud-controls-matrix" },
  { id: "BCR-08", title: "Backup and Recovery Testing", severity: "HIGH", category: "Database", provider: "All", framework: "CCM", description: "Test backup and recovery procedures at least annually to verify that data can be restored within the defined recovery time objective (RTO).", recommendation: "Automate backup verification. Perform quarterly restore tests on representative data sets. Document results.", docUrl: "https://cloudsecurityalliance.org/research/cloud-controls-matrix" },

  // CCC — Change Control & Configuration Management
  { id: "CCC-01", title: "Change Management Policy", severity: "MEDIUM", category: "Compute", provider: "All", framework: "CCM", description: "Establish a change management policy requiring quality testing, security impact analysis, and approval before deploying changes to production.", recommendation: "Implement a CHANGE board process. Use infrastructure-as-code (Terraform/CloudFormation) with PR reviews and automated testing gates.", docUrl: "https://cloudsecurityalliance.org/research/cloud-controls-matrix" },
  { id: "CCC-07", title: "Detection of Baseline Deviation", severity: "HIGH", category: "Compute", provider: "All", framework: "CCM", description: "Implement mechanisms to detect deviations from established baselines (configuration drift) in production environments.", recommendation: "Use AWS Config, Azure Policy, or GCP Organization Policy for continuous drift detection. Alert on unauthorized changes.", docUrl: "https://cloudsecurityalliance.org/research/cloud-controls-matrix" },

  // CEK — Cryptography, Encryption & Key Management
  { id: "CEK-01", title: "Encryption and Key Management Policy", severity: "HIGH", category: "Encryption", provider: "All", framework: "CCM", description: "Establish a policy for cryptography, encryption, and key management covering key generation, distribution, storage, rotation, revocation, and destruction.", recommendation: "Document cryptographic standards (AES-256, TLS 1.2+). Use cloud KMS (AWS KMS, Azure Key Vault, GCP Cloud KMS) for all key lifecycle management.", docUrl: "https://cloudsecurityalliance.org/research/cloud-controls-matrix" },
  { id: "CEK-03", title: "Data Encryption", severity: "CRITICAL", category: "Encryption", provider: "All", framework: "CCM", description: "Implement cryptographic controls to protect data in transit and at rest. Use industry-standard algorithms and key lengths.", recommendation: "Enforce TLS 1.2+ for all data in transit. Enable AES-256 encryption at rest for all storage services. Use customer-managed keys where possible.", docUrl: "https://cloudsecurityalliance.org/research/cloud-controls-matrix" },
  { id: "CEK-06", title: "Encryption Key Rotation", severity: "HIGH", category: "Encryption", provider: "All", framework: "CCM", description: "Cryptographic keys must be rotated based on a defined rotation schedule or after any security event that may have compromised the key.", recommendation: "Enable automatic annual key rotation on all KMS keys. Rotate keys immediately after personnel changes or suspected compromise.", docUrl: "https://cloudsecurityalliance.org/research/cloud-controls-matrix" },

  // DCS — Datacenter Security
  { id: "DCS-01", title: "Offsite Authorization Policy", severity: "MEDIUM", category: "Compute", provider: "All", framework: "CCM", description: "Authorize, document, and control all physical assets removed from data center facilities including equipment and storage media.", recommendation: "Implement an asset management system. Require approval for equipment removal. Track assets with RFID or barcodes.", docUrl: "https://cloudsecurityalliance.org/research/cloud-controls-matrix" },
  { id: "DCS-09", title: "Secure Area Authorization", severity: "HIGH", category: "IAM", provider: "All", framework: "CCM", description: "Restrict access to secure areas to authorized personnel only. Implement physical access controls with logging and regular access reviews.", recommendation: "Use badge access systems with audit logs. Review physical access quarterly. Implement multi-factor physical authentication for critical areas.", docUrl: "https://cloudsecurityalliance.org/research/cloud-controls-matrix" },

  // DSP — Data Security & Privacy Lifecycle Management
  { id: "DSP-01", title: "Security and Privacy Policy for Personal Data", severity: "HIGH", category: "IAM", provider: "All", framework: "CCM", description: "Establish, document, and maintain a security and privacy policy for personal data including collection, processing, storage, transmission, and disposal.", recommendation: "Implement a data classification policy. Map personal data flows. Appoint a Data Protection Officer (DPO) if required by GDPR.", docUrl: "https://cloudsecurityalliance.org/research/cloud-controls-matrix" },
  { id: "DSP-07", title: "Data Retention and Deletion", severity: "HIGH", category: "Storage", provider: "All", framework: "CCM", description: "Retain data for the minimum period required by legal/regulatory obligations. Securely delete data when no longer needed using approved methods.", recommendation: "Implement S3 lifecycle policies, Azure Blob retention, or GCP retention locks. Use cryptographic erasure or multi-pass deletion.", docUrl: "https://cloudsecurityalliance.org/research/cloud-controls-matrix" },
  { id: "DSP-10", title: "Sensitive Data Protection", severity: "CRITICAL", category: "Storage", provider: "All", framework: "CCM", description: "Protect sensitive data (PII, PHI, financial) through classification, access controls, encryption, and monitoring throughout its lifecycle.", recommendation: "Use AWS Macie, Azure Purview, or GCP DLP to discover and classify sensitive data. Apply controls based on classification.", docUrl: "https://cloudsecurityalliance.org/research/cloud-controls-matrix" },

  // GRC — Governance, Risk & Compliance
  { id: "GRC-01", title: "Governance and Risk Management Policy", severity: "MEDIUM", category: "Logging", provider: "All", framework: "CCM", description: "Establish governance and risk management policies aligned to organizational risk tolerance. Document risk appetite and ensure leadership accountability.", recommendation: "Implement an enterprise risk management (ERM) framework. Conduct annual risk assessments. Report risk posture to board/executive level.", docUrl: "https://cloudsecurityalliance.org/research/cloud-controls-matrix" },
  { id: "GRC-04", title: "Management Oversight", severity: "HIGH", category: "Logging", provider: "All", framework: "CCM", description: "Ensure management maintains oversight of information security policies, procedures, standards, and compliance with legal and regulatory requirements.", recommendation: "Establish a security steering committee. Conduct quarterly security reviews with management. Track compliance KPIs and report findings.", docUrl: "https://cloudsecurityalliance.org/research/cloud-controls-matrix" },

  // HRS — Human Resources Security
  { id: "HRS-01", title: "Background Screening Policy", severity: "MEDIUM", category: "IAM", provider: "All", framework: "CCM", description: "Establish a background screening policy for all personnel (employees, contractors, third parties) with access to organizational systems and data.", recommendation: "Require background checks before granting system access. Re-screen personnel with elevated privileges annually.", docUrl: "https://cloudsecurityalliance.org/research/cloud-controls-matrix" },
  { id: "HRS-09", title: "Termination and Offboarding", severity: "HIGH", category: "IAM", provider: "All", framework: "CCM", description: "Revoke all access rights, retrieve organizational assets, and disable accounts within defined SLOs upon employee or contractor termination.", recommendation: "Automate deprovisioning via HR-to-IAM integration. Target: access revoked within 1 hour of termination notice. Audit monthly.", docUrl: "https://cloudsecurityalliance.org/research/cloud-controls-matrix" },

  // IAM — Identity & Access Management
  { id: "IAM-01", title: "Identity and Access Management Policy", severity: "HIGH", category: "IAM", provider: "All", framework: "CCM", description: "Establish an IAM policy covering identity lifecycle, authentication, authorization, privileged access management, and periodic access reviews.", recommendation: "Implement a formal IAM policy. Use an IdP (Okta, Azure AD, Google Workspace). Review all access quarterly.", docUrl: "https://cloudsecurityalliance.org/research/cloud-controls-matrix" },
  { id: "IAM-02", title: "Strong Password Policy and Procedures", severity: "HIGH", category: "IAM", provider: "All", framework: "CCM", description: "Implement and enforce a strong password policy requiring minimum length, complexity, and regular rotation for all user and service accounts.", recommendation: "Enforce minimum 14 characters, complexity rules, and 90-day rotation. Use a password manager. Disable password reuse for 12 cycles.", docUrl: "https://cloudsecurityalliance.org/research/cloud-controls-matrix" },
  { id: "IAM-07", title: "Multi-Factor Authentication", severity: "CRITICAL", category: "IAM", provider: "All", framework: "CCM", description: "Require multi-factor authentication (MFA) for all user access to cloud management consoles, privileged accounts, and remote access systems.", recommendation: "Enforce MFA for all console logins. Use hardware security keys (FIDO2/WebAuthn) for privileged accounts. Audit MFA compliance monthly.", docUrl: "https://cloudsecurityalliance.org/research/cloud-controls-matrix" },
  { id: "IAM-09", title: "User Access Reviews", severity: "HIGH", category: "IAM", provider: "All", framework: "CCM", description: "Perform periodic reviews of user access rights (at least quarterly for privileged access, annually for standard users) and revoke unnecessary access.", recommendation: "Use AWS IAM Access Analyzer, Azure Access Reviews, or GCP IAM Recommender. Document reviews and approvals.", docUrl: "https://cloudsecurityalliance.org/research/cloud-controls-matrix" },

  // IPY — Interoperability & Portability
  { id: "IPY-01", title: "Interoperability and Portability Policy", severity: "LOW", category: "Compute", provider: "All", framework: "CCM", description: "Establish policies and procedures to ensure interoperability and portability of data and services, reducing vendor lock-in risk.", recommendation: "Document data formats and APIs. Use open standards (OpenAPI, CNCF). Include portability clauses in cloud contracts.", docUrl: "https://cloudsecurityalliance.org/research/cloud-controls-matrix" },
  { id: "IPY-04", title: "Application Portability", severity: "MEDIUM", category: "Compute", provider: "All", framework: "CCM", description: "Design applications using portable architectures and open standards to enable migration between cloud providers without significant rework.", recommendation: "Use containerization (Docker/Kubernetes). Avoid proprietary cloud services without abstraction layers. Use multi-cloud IaC.", docUrl: "https://cloudsecurityalliance.org/research/cloud-controls-matrix" },

  // I&S — Infrastructure & Virtualization Security
  { id: "I&S-01", title: "Infrastructure and Virtualization Security Policy", severity: "HIGH", category: "Compute", provider: "All", framework: "CCM", description: "Establish and maintain policies for securing cloud infrastructure, hypervisors, and virtualization components from unauthorized access and configuration drift.", recommendation: "Apply CIS Benchmarks for cloud infrastructure. Implement hypervisor hardening guidelines. Use immutable infrastructure patterns.", docUrl: "https://cloudsecurityalliance.org/research/cloud-controls-matrix" },
  { id: "I&S-04", title: "OS Hardening and Base Controls", severity: "HIGH", category: "Compute", provider: "All", framework: "CCM", description: "Harden all operating system images used in cloud infrastructure by removing unnecessary services, applying security patches, and enforcing baseline configurations.", recommendation: "Use CIS hardened AMIs/VM images. Scan for vulnerabilities with AWS Inspector, Azure Defender, or GCP Security Command Center.", docUrl: "https://cloudsecurityalliance.org/research/cloud-controls-matrix" },
  { id: "I&S-07", title: "Network Security", severity: "CRITICAL", category: "Networking", provider: "All", framework: "CCM", description: "Implement network security controls including firewalls, intrusion detection/prevention, micro-segmentation, and zero-trust architecture principles.", recommendation: "Deploy WAF for internet-facing services. Enable VPC Flow Logs. Implement network segmentation with least-privilege security groups.", docUrl: "https://cloudsecurityalliance.org/research/cloud-controls-matrix" },

  // LOG — Logging and Monitoring
  { id: "LOG-01", title: "Logging and Monitoring Policy", severity: "HIGH", category: "Logging", provider: "All", framework: "CCM", description: "Establish a logging and monitoring policy covering log retention periods, centralization, integrity protection, and incident response integration.", recommendation: "Centralize logs in a SIEM. Retain security logs for minimum 1 year. Protect log integrity with WORM storage or digital signatures.", docUrl: "https://cloudsecurityalliance.org/research/cloud-controls-matrix" },
  { id: "LOG-05", title: "Audit Logging", severity: "HIGH", category: "Logging", provider: "All", framework: "CCM", description: "Log all security-relevant events including authentication, authorization, privileged access, configuration changes, and data access across all cloud services.", recommendation: "Enable CloudTrail (AWS), Activity Log (Azure), or Cloud Audit Logs (GCP) for all services. Include management and data plane events.", docUrl: "https://cloudsecurityalliance.org/research/cloud-controls-matrix" },
  { id: "LOG-06", title: "Security Monitoring and Alerting", severity: "HIGH", category: "Logging", provider: "All", framework: "CCM", description: "Implement real-time monitoring and alerting for security events. Define alert thresholds, escalation paths, and response SLOs.", recommendation: "Use AWS GuardDuty, Azure Sentinel, or GCP SCC for threat detection. Define P1/P2/P3 alert tiers with response SLOs.", docUrl: "https://cloudsecurityalliance.org/research/cloud-controls-matrix" },
  { id: "LOG-13", title: "Clock Synchronization", severity: "LOW", category: "Logging", provider: "All", framework: "CCM", description: "Synchronize all system clocks to an authoritative time source (NTP) to ensure consistent and accurate audit log timestamps.", recommendation: "Use AWS Time Sync Service, Azure NTP, or GCP NTP. Verify all instances sync to the authorized time source.", docUrl: "https://cloudsecurityalliance.org/research/cloud-controls-matrix" },

  // SEF — Security Incident Management, E-Discovery & Cloud Forensics
  { id: "SEF-01", title: "Incident Management Policy", severity: "HIGH", category: "Logging", provider: "All", framework: "CCM", description: "Establish an incident management policy and response plan covering detection, classification, containment, eradication, recovery, and post-incident review.", recommendation: "Maintain an incident response runbook. Define incident severity levels. Conduct tabletop exercises semi-annually. Test detection capabilities.", docUrl: "https://cloudsecurityalliance.org/research/cloud-controls-matrix" },
  { id: "SEF-05", title: "Incident Response Testing", severity: "MEDIUM", category: "Logging", provider: "All", framework: "CCM", description: "Test the incident response plan at least annually through tabletop exercises, simulations, or red team/blue team exercises.", recommendation: "Conduct annual IR simulation including cloud-specific scenarios (data breach, account compromise, ransomware). Document lessons learned.", docUrl: "https://cloudsecurityalliance.org/research/cloud-controls-matrix" },

  // STA — Supply Chain Management, Transparency & Accountability
  { id: "STA-01", title: "Supply Chain Management Policy", severity: "MEDIUM", category: "Compute", provider: "All", framework: "CCM", description: "Establish a supply chain management policy to assess and manage security risks from third-party suppliers, sub-processors, and software dependencies.", recommendation: "Conduct third-party risk assessments before onboarding. Review SOC 2 reports. Include security requirements in contracts (DPA, SLA).", docUrl: "https://cloudsecurityalliance.org/research/cloud-controls-matrix" },
  { id: "STA-08", title: "Third-Party Audits", severity: "HIGH", category: "Logging", provider: "All", framework: "CCM", description: "Require cloud service providers to undergo independent third-party audits (SOC 2, ISO 27001, CSA STAR) and make results available to customers.", recommendation: "Request current SOC 2 Type II reports from CSPs. Review audit findings. Verify remediation of critical findings.", docUrl: "https://cloudsecurityalliance.org/research/cloud-controls-matrix" },

  // TVM — Threat and Vulnerability Management
  { id: "TVM-01", title: "Antivirus and Malware Protection", severity: "HIGH", category: "Compute", provider: "All", framework: "CCM", description: "Implement antivirus and anti-malware protection on all applicable systems. Ensure definitions are updated at least daily.", recommendation: "Deploy AWS GuardDuty Malware Protection, Azure Defender for Endpoint, or GCP Chronicle for cloud workload protection.", docUrl: "https://cloudsecurityalliance.org/research/cloud-controls-matrix" },
  { id: "TVM-02", title: "Vulnerability Management Policy", severity: "HIGH", category: "Compute", provider: "All", framework: "CCM", description: "Establish a vulnerability management policy defining scanning frequency, severity-based remediation SLOs, and exception handling.", recommendation: "Perform weekly automated vulnerability scans. Patch Critical within 24h, High within 7 days, Medium within 30 days.", docUrl: "https://cloudsecurityalliance.org/research/cloud-controls-matrix" },
  { id: "TVM-09", title: "Penetration Testing", severity: "HIGH", category: "Compute", provider: "All", framework: "CCM", description: "Conduct penetration testing of cloud infrastructure and applications at least annually or after significant changes by qualified internal or external teams.", recommendation: "Engage CREST/OSCP-certified pen testers. Test internal and external attack surfaces. Track and remediate findings within defined SLOs.", docUrl: "https://cloudsecurityalliance.org/research/cloud-controls-matrix" },

  // UEM — Universal Endpoint Management
  { id: "UEM-01", title: "Endpoint Devices Policy", severity: "MEDIUM", category: "Compute", provider: "All", framework: "CCM", description: "Establish an endpoint device management policy covering corporate-owned and BYOD devices that access cloud resources.", recommendation: "Enforce MDM/UEM (Intune, Jamf, Workspace ONE) for all devices. Require device compliance checks before granting cloud access.", docUrl: "https://cloudsecurityalliance.org/research/cloud-controls-matrix" },
  { id: "UEM-06", title: "Endpoint Security Baseline", severity: "HIGH", category: "Compute", provider: "All", framework: "CCM", description: "Define and enforce a security baseline for all endpoints including encryption, patch level, endpoint protection, and screen lock requirements.", recommendation: "Require BitLocker/FileVault encryption. Enforce OS patching within 30 days. Deploy EDR solution. Enforce auto-lock after 5 minutes.", docUrl: "https://cloudsecurityalliance.org/research/cloud-controls-matrix" },
  { id: "UEM-14", title: "Remote Work Policies", severity: "MEDIUM", category: "Networking", provider: "All", framework: "CCM", description: "Establish remote work policies governing the security of cloud access from remote locations including VPN requirements, home network security, and device controls.", recommendation: "Require VPN or Zero Trust Network Access (ZTNA) for all remote cloud access. Block split-tunneling. Enforce conditional access policies.", docUrl: "https://cloudsecurityalliance.org/research/cloud-controls-matrix" },

  // ═══════════════════════════════════════════════════════════════════════
  // CIS Docker Benchmark v1.6.0 (2024)
  // https://www.cisecurity.org/benchmark/docker
  // ═══════════════════════════════════════════════════════════════════════

  // Host Configuration
  { id: "DKR 1.1", title: "Ensure a separate partition for containers has been created", severity: "HIGH", category: "Host Config", provider: "Docker", framework: "Docker", description: "All Docker containers and their data are stored under /var/lib/docker. This directory might fill up fast, making the host and Docker unusable. Create a separate partition for Docker.", recommendation: "Create a separate partition or volume for /var/lib/docker. Use --data-root flag to configure custom Docker root directory on dedicated storage.", docUrl: "https://docs.docker.com/engine/reference/commandline/dockerd/#daemon-data-directory" },
  { id: "DKR 1.2", title: "Ensure Docker is kept up to date", severity: "HIGH", category: "Host Config", provider: "Docker", framework: "Docker", description: "Running outdated Docker versions exposes the host to known vulnerabilities. Keep Docker Engine updated to the latest stable release.", recommendation: "Update Docker Engine to the latest stable version. Subscribe to Docker security advisories. Test updates in staging before production.", docUrl: "https://docs.docker.com/engine/install/" },

  // Docker Daemon
  { id: "DKR 2.1", title: "Ensure network traffic is restricted between containers", severity: "HIGH", category: "Network", provider: "Docker", framework: "Docker", description: "By default, unrestricted network traffic is enabled between all containers on the same host. Restrict inter-container communication.", recommendation: "Set --icc=false on Docker daemon or use docker network create with --internal flag. Use user-defined bridge networks with explicit links.", docUrl: "https://docs.docker.com/network/drivers/bridge/#manage-a-user-defined-bridge" },
  { id: "DKR 2.2", title: "Ensure the logging level is set to 'info'", severity: "MEDIUM", category: "Logging", provider: "Docker", framework: "Docker", description: "Setting the log level to info ensures appropriate information is captured for troubleshooting and security monitoring.", recommendation: "Set --log-level=info in Docker daemon configuration (/etc/docker/daemon.json). Avoid debug level in production.", docUrl: "https://docs.docker.com/config/daemon/logs/" },
  { id: "DKR 2.3", title: "Ensure Docker daemon audit logging is configured", severity: "HIGH", category: "Logging", provider: "Docker", framework: "Docker", description: "Audit all Docker daemon activities to track security-relevant events including container lifecycle, image operations, and configuration changes.", recommendation: "Add Docker daemon files and directories to auditd rules: -w /usr/bin/dockerd -k docker -w /var/lib/docker -k docker -w /etc/docker -k docker", docUrl: "https://docs.docker.com/engine/security/" },
  { id: "DKR 2.5", title: "Ensure insecure registries are not used", severity: "CRITICAL", category: "Image Security", provider: "Docker", framework: "Docker", description: "Docker should not be configured to use insecure (HTTP) registries. All registry communications must use TLS encryption.", recommendation: "Remove any --insecure-registry flags from daemon configuration. Use only HTTPS registries. Configure private registries with valid TLS certificates.", docUrl: "https://docs.docker.com/registry/insecure/" },
  { id: "DKR 2.6", title: "Ensure TLS authentication for Docker daemon is configured", severity: "CRITICAL", category: "Network", provider: "Docker", framework: "Docker", description: "Docker daemon should require TLS client authentication to prevent unauthorized access to the Docker API.", recommendation: "Configure --tlsverify, --tlscacert, --tlscert, and --tlskey flags on Docker daemon. Use mutual TLS authentication.", docUrl: "https://docs.docker.com/engine/security/protect-access/" },

  // Docker Images
  { id: "DKR 4.1", title: "Ensure a user for the container has been created", severity: "HIGH", category: "Image Security", provider: "Docker", framework: "Docker", description: "Containers should not run as root. Create a dedicated non-root user in Dockerfiles to reduce container breakout risk.", recommendation: "Add USER directive in Dockerfile after installing packages. Use 'USER appuser' with a specific UID/GID. Avoid running as root.", docUrl: "https://docs.docker.com/develop/develop-images/instructions/#user" },
  { id: "DKR 4.2", title: "Ensure images are scanned for vulnerabilities", severity: "CRITICAL", category: "Image Security", provider: "Docker", framework: "Docker", description: "Container images should be scanned for known vulnerabilities before deployment. Use automated scanning in CI/CD pipelines.", recommendation: "Integrate Trivy, Snyk, or Docker Scout into CI/CD. Block deployment of images with Critical/High CVEs. Scan base images weekly.", docUrl: "https://docs.docker.com/scout/" },
  { id: "DKR 4.3", title: "Ensure only trusted base images are used", severity: "HIGH", category: "Image Security", provider: "Docker", framework: "Docker", description: "Use only official or verified base images from trusted registries. Avoid using unknown or community images without verification.", recommendation: "Use Docker Official Images or Verified Publisher images. Pin images to specific SHA256 digests. Maintain a curated list of approved base images.", docUrl: "https://docs.docker.com/trusted-content/official-images/" },
  { id: "DKR 4.6", title: "Ensure HEALTHCHECK instructions are added", severity: "MEDIUM", category: "Runtime", provider: "Docker", framework: "Docker", description: "Add HEALTHCHECK instruction to Dockerfiles to enable container health monitoring and automatic restart of unhealthy containers.", recommendation: "Add HEALTHCHECK --interval=30s --timeout=10s --retries=3 CMD [command] to Dockerfile. Use appropriate health check endpoints.", docUrl: "https://docs.docker.com/reference/dockerfile/#healthcheck" },

  // Container Runtime
  { id: "DKR 5.1", title: "Ensure privileged containers are not used", severity: "CRITICAL", category: "Runtime", provider: "Docker", framework: "Docker", description: "Privileged containers have full access to the host's devices and kernel capabilities. Never use --privileged flag in production.", recommendation: "Remove --privileged flag. Use --cap-add to grant only specific capabilities needed. Use --security-opt for fine-grained security.", docUrl: "https://docs.docker.com/engine/reference/run/#runtime-privilege-and-linux-capabilities" },
  { id: "DKR 5.2", title: "Ensure sensitive host directories are not mounted", severity: "CRITICAL", category: "Runtime", provider: "Docker", framework: "Docker", description: "Sensitive host directories (/, /boot, /dev, /etc, /lib, /proc, /sys, /usr) should not be mounted into containers.", recommendation: "Audit volume mounts with 'docker inspect'. Remove mounts to sensitive host paths. Use named volumes or tmpfs for temporary data.", docUrl: "https://docs.docker.com/storage/volumes/" },
  { id: "DKR 5.4", title: "Ensure container resource limits (CPU/memory) are set", severity: "HIGH", category: "Runtime", provider: "Docker", framework: "Docker", description: "Containers without resource limits can consume all host resources, causing denial of service. Set CPU and memory limits.", recommendation: "Use --memory, --memory-swap, --cpus flags. In Docker Compose: deploy.resources.limits. Set both memory and CPU limits for every container.", docUrl: "https://docs.docker.com/config/containers/resource_constraints/" },
  { id: "DKR 5.10", title: "Ensure secrets are not stored in Dockerfiles or images", severity: "CRITICAL", category: "Image Security", provider: "Docker", framework: "Docker", description: "Secrets (passwords, API keys, tokens) must never be hardcoded in Dockerfiles or baked into images. Use runtime secret injection.", recommendation: "Use Docker secrets, environment variables from vault, or mount secrets at runtime. Use multi-stage builds. Scan images with tools like truffleHog.", docUrl: "https://docs.docker.com/engine/swarm/secrets/" },

  // ═══════════════════════════════════════════════════════════════════════
  // CIS Kubernetes Benchmark v1.8.0 (2024)
  // https://www.cisecurity.org/benchmark/kubernetes
  // ═══════════════════════════════════════════════════════════════════════

  // Control Plane
  { id: "K8S 1.1", title: "Ensure API server --anonymous-auth is set to false", severity: "CRITICAL", category: "API Server", provider: "K8s", framework: "K8s", description: "Anonymous authentication allows unauthenticated requests to the API server. Disable it to enforce authentication for all requests.", recommendation: "Set --anonymous-auth=false on kube-apiserver. Ensure all API requests require valid authentication credentials.", docUrl: "https://kubernetes.io/docs/reference/access-authn-authz/authentication/" },
  { id: "K8S 1.2", title: "Ensure API server --authorization-mode is not set to AlwaysAllow", severity: "CRITICAL", category: "API Server", provider: "K8s", framework: "K8s", description: "AlwaysAllow authorization mode grants all requests without any authorization check. Use RBAC or Node authorization.", recommendation: "Set --authorization-mode=RBAC,Node on kube-apiserver. Never use AlwaysAllow in production clusters.", docUrl: "https://kubernetes.io/docs/reference/access-authn-authz/authorization/" },
  { id: "K8S 1.3", title: "Ensure API server --audit-log-path is configured", severity: "HIGH", category: "API Server", provider: "K8s", framework: "K8s", description: "Kubernetes API server audit logging records all requests for security monitoring, compliance, and incident investigation.", recommendation: "Set --audit-log-path=/var/log/kubernetes/audit.log --audit-policy-file=/etc/kubernetes/audit-policy.yaml with appropriate retention.", docUrl: "https://kubernetes.io/docs/tasks/debug/debug-cluster/audit/" },
  { id: "K8S 1.4", title: "Ensure API server uses TLS certificates", severity: "CRITICAL", category: "API Server", provider: "K8s", framework: "K8s", description: "The API server must use TLS for all communications. Ensure --tls-cert-file and --tls-private-key-file are configured.", recommendation: "Configure --tls-cert-file and --tls-private-key-file with valid certificates. Rotate certificates before expiry. Use cert-manager for automation.", docUrl: "https://kubernetes.io/docs/tasks/tls/managing-tls-in-a-cluster/" },

  // RBAC & Auth
  { id: "K8S 3.1", title: "Ensure RBAC is enabled and properly configured", severity: "CRITICAL", category: "RBAC", provider: "K8s", framework: "K8s", description: "Role-Based Access Control (RBAC) must be enabled to enforce least-privilege access. Default service accounts should have minimal permissions.", recommendation: "Set --authorization-mode=RBAC. Create specific Roles/ClusterRoles with minimal permissions. Avoid cluster-admin for workloads.", docUrl: "https://kubernetes.io/docs/reference/access-authn-authz/rbac/" },
  { id: "K8S 3.2", title: "Ensure default service account is not used", severity: "HIGH", category: "RBAC", provider: "K8s", framework: "K8s", description: "Pods should not use the default service account. Create dedicated service accounts with minimal RBAC permissions for each workload.", recommendation: "Set automountServiceAccountToken: false on default SA. Create per-workload service accounts. Bind only required roles.", docUrl: "https://kubernetes.io/docs/tasks/configure-pod-container/configure-service-account/" },

  // Pod Security
  { id: "K8S 4.1", title: "Ensure pods do not run as root", severity: "CRITICAL", category: "Pod Security", provider: "K8s", framework: "K8s", description: "Containers running as root inside pods can escalate privileges to the node. Enforce non-root execution via security contexts.", recommendation: "Set securityContext.runAsNonRoot: true and runAsUser: 1000 on pod specs. Use Pod Security Standards (Restricted profile).", docUrl: "https://kubernetes.io/docs/concepts/security/pod-security-standards/" },
  { id: "K8S 4.2", title: "Ensure pods do not allow privilege escalation", severity: "CRITICAL", category: "Pod Security", provider: "K8s", framework: "K8s", description: "allowPrivilegeEscalation enables a process to gain more privileges than its parent. Disable it on all containers.", recommendation: "Set securityContext.allowPrivilegeEscalation: false on all containers. Enforce via Pod Security Admission (Restricted).", docUrl: "https://kubernetes.io/docs/concepts/security/pod-security-standards/" },
  { id: "K8S 4.3", title: "Ensure pods drop all capabilities and add only required ones", severity: "HIGH", category: "Pod Security", provider: "K8s", framework: "K8s", description: "Linux capabilities give granular root permissions. Containers should drop ALL capabilities and add back only what is explicitly needed.", recommendation: "Set securityContext.capabilities: { drop: ['ALL'], add: ['NET_BIND_SERVICE'] } — only add what is explicitly required.", docUrl: "https://kubernetes.io/docs/tasks/configure-pod-container/security-context/#set-capabilities-for-a-container" },
  { id: "K8S 4.4", title: "Ensure read-only root filesystem is enabled", severity: "MEDIUM", category: "Pod Security", provider: "K8s", framework: "K8s", description: "A read-only root filesystem prevents writes to the container filesystem, limiting attacker capability after compromise.", recommendation: "Set securityContext.readOnlyRootFilesystem: true. Use emptyDir volumes for temporary writable directories like /tmp.", docUrl: "https://kubernetes.io/docs/concepts/security/pod-security-standards/" },

  // Network & Secrets
  { id: "K8S 5.1", title: "Ensure NetworkPolicies are defined for all namespaces", severity: "HIGH", category: "Network", provider: "K8s", framework: "K8s", description: "By default, all pods can communicate with all other pods. NetworkPolicies enforce micro-segmentation and zero-trust networking.", recommendation: "Create default-deny NetworkPolicies per namespace. Then allow only required ingress/egress traffic explicitly.", docUrl: "https://kubernetes.io/docs/concepts/services-networking/network-policies/" },
  { id: "K8S 5.2", title: "Ensure Kubernetes Secrets are encrypted at rest", severity: "CRITICAL", category: "Secrets", provider: "K8s", framework: "K8s", description: "Kubernetes Secrets are stored in etcd in base64 encoding by default, which is NOT encryption. Enable encryption at rest.", recommendation: "Configure EncryptionConfiguration with aescbc or kms provider. Use external secret stores (Vault, AWS Secrets Manager) for production.", docUrl: "https://kubernetes.io/docs/tasks/administer-cluster/encrypt-data/" },
  { id: "K8S 5.3", title: "Ensure Secrets are not used as environment variables", severity: "HIGH", category: "Secrets", provider: "K8s", framework: "K8s", description: "Secrets exposed as environment variables can leak via logs, crash dumps, or child processes. Mount secrets as volumes instead.", recommendation: "Use volume mounts to project secrets as files. Avoid envFrom with secretRef. Use external secret operators (ESO, Vault) for rotation.", docUrl: "https://kubernetes.io/docs/concepts/configuration/secret/#using-secrets" },

  // Resource Management
  { id: "K8S 6.1", title: "Ensure resource requests and limits are set for all pods", severity: "HIGH", category: "Resources", provider: "K8s", framework: "K8s", description: "Pods without resource requests/limits can consume all node resources, causing evictions and instability. Always set both.", recommendation: "Set resources.requests and resources.limits for CPU and memory on every container. Use LimitRanges as namespace-level defaults.", docUrl: "https://kubernetes.io/docs/concepts/configuration/manage-resources-containers/" },
  { id: "K8S 6.2", title: "Ensure namespaces have ResourceQuotas defined", severity: "MEDIUM", category: "Resources", provider: "K8s", framework: "K8s", description: "ResourceQuotas prevent a single namespace from consuming excessive cluster resources. Define quotas for all non-system namespaces.", recommendation: "Create ResourceQuota objects defining limits for pods, services, CPU, memory, and storage per namespace.", docUrl: "https://kubernetes.io/docs/concepts/policy/resource-quotas/" },
];

const CLOUD_RULES = COMPLIANCE_RULES.filter(r => ["CIS", "NIST", "CCM"].includes(r.framework));
const CONTAINER_RULES = COMPLIANCE_RULES.filter(r => ["Docker", "K8s"].includes(r.framework));

const CLOUD_FRAMEWORKS = ["All", "CIS", "NIST", "CCM"];
const CONTAINER_FRAMEWORKS = ["All", "Docker", "K8s"];
const SEVERITIES = ["All", "CRITICAL", "HIGH", "MEDIUM", "LOW"];

const PROVIDER_COLORS = {
  AWS: { bg: "rgba(255,153,0,0.08)", color: "#ff9900", border: "rgba(255,153,0,0.2)" },
  Azure: { bg: "rgba(0,120,212,0.08)", color: "#0078d4", border: "rgba(0,120,212,0.2)" },
  GCP: { bg: "rgba(66,133,244,0.08)", color: "#4285f4", border: "rgba(66,133,244,0.2)" },
  Docker: { bg: "rgba(13,183,237,0.08)", color: "#0db7ed", border: "rgba(13,183,237,0.2)" },
  "K8s": { bg: "rgba(50,109,230,0.08)", color: "#326de6", border: "rgba(50,109,230,0.2)" },
  All: { bg: "rgba(139,92,246,0.08)", color: "#8b5cf6", border: "rgba(139,92,246,0.2)" },
};

const FRAMEWORK_COLORS = {
  CIS: { bg: "rgba(34,197,94,0.08)", color: "#16a34a", border: "rgba(34,197,94,0.2)" },
  NIST: { bg: "rgba(59,130,246,0.08)", color: "#2563eb", border: "rgba(59,130,246,0.2)" },
  CCM: { bg: "rgba(234,88,12,0.08)", color: "#ea580c", border: "rgba(234,88,12,0.2)" },
  Docker: { bg: "rgba(13,183,237,0.08)", color: "#0db7ed", border: "rgba(13,183,237,0.2)" },
  "K8s": { bg: "rgba(50,109,230,0.08)", color: "#326de6", border: "rgba(50,109,230,0.2)" },
};

/* ── Reusable Rule Card ─────────────────────────────────────────────── */
function RuleCard({ rule, isExpanded, onToggle }) {
  const pc = PROVIDER_COLORS[rule.provider] || PROVIDER_COLORS.All;
  const fc = FRAMEWORK_COLORS[rule.framework] || FRAMEWORK_COLORS.CIS;
  return (
    <div className="glass-card rule-card" onClick={onToggle} style={{ cursor: "pointer" }}>
      <div className="card-body">
        <div style={{ display: "flex", justifyContent: "space-between", alignItems: "flex-start", marginBottom: 10 }}>
          <div style={{ display: "flex", alignItems: "center", gap: 6, flexWrap: "wrap" }}>
            <a href={rule.docUrl} target="_blank" rel="noopener noreferrer" onClick={(e) => e.stopPropagation()}
              className="rule-id" style={{ fontSize: 13, textDecoration: "none", color: "var(--accent-primary)", borderBottom: "1px dashed var(--accent-primary)" }}
            >{rule.id}</a>
            <span style={{ fontSize: 9, fontWeight: 700, padding: "2px 6px", borderRadius: 99, background: fc.bg, color: fc.color, border: `1px solid ${fc.border}`, textTransform: "uppercase", letterSpacing: 0.5 }}>{rule.framework}</span>
            <span style={{ fontSize: 9, fontWeight: 700, padding: "2px 6px", borderRadius: 99, background: pc.bg, color: pc.color, border: `1px solid ${pc.border}` }}>
              {rule.provider === "All" ? "All Clouds" : rule.provider}
            </span>
          </div>
          <span className={`severity-badge ${rule.severity.toLowerCase()}`}>{rule.severity}</span>
        </div>
        <h4 style={{ fontSize: 14, fontWeight: 600, marginBottom: 8, lineHeight: 1.4 }}>{rule.title}</h4>
        <p style={{ fontSize: 12, color: "var(--text-secondary)", lineHeight: 1.5, marginBottom: 10 }}>{rule.description}</p>
        {isExpanded && (
          <div className="animate-fade-in" style={{ marginTop: 12 }}>
            <div style={{ padding: "12px 14px", background: "rgba(255,122,0,0.04)", borderRadius: 10, border: "1px solid rgba(255,122,0,0.1)", marginBottom: 10 }}>
              <p style={{ fontSize: 11, fontWeight: 700, color: "var(--accent-amber)", marginBottom: 4 }}>
                <Icon name="circle-check" size={12} style={{ marginRight: 4 }} /> Recommendation
              </p>
              <p style={{ fontSize: 12, color: "var(--text-secondary)", lineHeight: 1.6 }}>{rule.recommendation}</p>
            </div>
            {rule.docUrl && (
              <a href={rule.docUrl} target="_blank" rel="noopener noreferrer" onClick={(e) => e.stopPropagation()}
                style={{ display: "inline-flex", alignItems: "center", gap: 6, fontSize: 12, fontWeight: 600, color: "var(--accent-primary)", textDecoration: "none", padding: "6px 12px", borderRadius: 6, background: "rgba(255,122,0,0.06)", border: "1px solid rgba(255,122,0,0.15)", transition: "all 0.2s" }}
                onMouseEnter={(e) => e.target.style.background = "rgba(255,122,0,0.12)"}
                onMouseLeave={(e) => e.target.style.background = "rgba(255,122,0,0.06)"}
              >
                <Icon name="arrow-up" size={12} style={{ transform: "rotate(45deg)" }} /> View Official Documentation
              </a>
            )}
          </div>
        )}
        <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", marginTop: 10 }}>
          <span className="category-tag">{rule.category}</span>
          <span style={{ fontSize: 11, color: "var(--text-muted)" }}>{isExpanded ? "Click to collapse" : "Click for details"}</span>
        </div>
      </div>
    </div>
  );
}

export default function CISRulesView() {
  // Cloud section state
  const [cloudSearch, setCloudSearch] = useState("");
  const [cloudCategory, setCloudCategory] = useState("All");
  const [cloudSeverity, setCloudSeverity] = useState("All");
  const [cloudFramework, setCloudFramework] = useState("All");
  const [expandedRule, setExpandedRule] = useState(null);

  // Container section state
  const [containerSearch, setContainerSearch] = useState("");
  const [containerCategory, setContainerCategory] = useState("All");
  const [containerSeverity, setContainerSeverity] = useState("All");
  const [containerFramework, setContainerFramework] = useState("All");

  const cloudCategories = ["All", ...Array.from(new Set(CLOUD_RULES.map((r) => r.category))).sort()];
  const containerCategories = ["All", ...Array.from(new Set(CONTAINER_RULES.map((r) => r.category))).sort()];

  // Cloud filtering
  const filteredCloud = CLOUD_RULES.filter((r) => {
    const q = cloudSearch.toLowerCase();
    const matchesSearch = !cloudSearch || r.title.toLowerCase().includes(q) || r.id.toLowerCase().includes(q) || r.description.toLowerCase().includes(q) || r.category.toLowerCase().includes(q) || r.recommendation.toLowerCase().includes(q);
    return matchesSearch && (cloudCategory === "All" || r.category === cloudCategory) && (cloudSeverity === "All" || r.severity === cloudSeverity) && (cloudFramework === "All" || r.framework === cloudFramework);
  });

  // Container filtering
  const filteredContainer = CONTAINER_RULES.filter((r) => {
    const q = containerSearch.toLowerCase();
    const matchesSearch = !containerSearch || r.title.toLowerCase().includes(q) || r.id.toLowerCase().includes(q) || r.description.toLowerCase().includes(q) || r.category.toLowerCase().includes(q) || r.recommendation.toLowerCase().includes(q);
    return matchesSearch && (containerCategory === "All" || r.category === containerCategory) && (containerSeverity === "All" || r.severity === containerSeverity) && (containerFramework === "All" || r.framework === containerFramework);
  });

  const cloudCounts = {
    All: CLOUD_RULES.length,
    CIS: CLOUD_RULES.filter(r => r.framework === "CIS").length,
    NIST: CLOUD_RULES.filter(r => r.framework === "NIST").length,
    CCM: CLOUD_RULES.filter(r => r.framework === "CCM").length,
  };

  const containerCounts = {
    All: CONTAINER_RULES.length,
    Docker: CONTAINER_RULES.filter(r => r.framework === "Docker").length,
    "K8s": CONTAINER_RULES.filter(r => r.framework === "K8s").length,
  };

  return (
    <div>
      {/* ═══════════════════════════════════════════════════════════════════
           SECTION 1: CLOUD COMPLIANCE RULES 
          ═══════════════════════════════════════════════════════════════════ */}
      <div className="page-header">
        <h2>Cloud Compliance Rules</h2>
        <p>Reference catalog of CIS Benchmark, NIST 800-53, and CSA CCM v4.1 compliance controls — applicable across AWS, Azure, and GCP</p>
      </div>

      {/* Cloud Framework Tabs */}
      <div style={{ display: "flex", gap: 10, marginBottom: 12, alignItems: "center", flexWrap: "wrap" }}>
        {CLOUD_FRAMEWORKS.map((f) => (
          <button key={f} className={`period-btn ${cloudFramework === f ? "active" : ""}`} onClick={() => setCloudFramework(f)}
            style={{ display: "flex", alignItems: "center", gap: 6, fontWeight: 600 }}>
            {f === "CIS" && <Icon name="shield" size={14} />}
            {f === "NIST" && <Icon name="clipboard" size={14} />}
            {f === "CCM" && <Icon name="cloud-plus" size={14} />}
            {f} <span style={{ opacity: 0.7, fontSize: 11 }}>({cloudCounts[f]})</span>
          </button>
        ))}
        <span style={{ marginLeft: "auto", fontSize: 12, color: "var(--text-muted)", display: "flex", alignItems: "center", gap: 6 }}>
          <img src="/logos/aws.svg" alt="AWS" style={{ width: 16, height: 16, opacity: 0.7 }} />
          <img src="/logos/azure.svg" alt="Azure" style={{ width: 16, height: 16, opacity: 0.7 }} />
          <img src="/logos/gcp.svg" alt="GCP" style={{ width: 16, height: 16, opacity: 0.7 }} />
          Controls apply to all cloud providers
        </span>
      </div>

      {/* Cloud Search & Filters */}
      <div className="glass-card" style={{ marginBottom: 20 }}>
        <div className="card-body" style={{ display: "flex", gap: 12, flexWrap: "wrap", alignItems: "center" }}>
          <div className="input-wrapper" style={{ flex: 1, minWidth: 200 }}>
            <span className="input-icon"><Icon name="search" size={16} /></span>
            <input type="text" placeholder="Search cloud rules by ID, title, description..." value={cloudSearch} onChange={(e) => setCloudSearch(e.target.value)} style={{ width: "100%" }} />
          </div>
          <select className="filter-select" value={cloudCategory} onChange={(e) => setCloudCategory(e.target.value)}>
            {cloudCategories.map((c) => <option key={c} value={c}>{c === "All" ? "All Categories" : c}</option>)}
          </select>
          <select className="filter-select" value={cloudSeverity} onChange={(e) => setCloudSeverity(e.target.value)}>
            {SEVERITIES.map((s) => <option key={s} value={s}>{s === "All" ? "All Severities" : s}</option>)}
          </select>
          {cloudSearch && (
            <button onClick={() => setCloudSearch("")} style={{ padding: "8px 14px", border: "1px solid var(--border-glass)", borderRadius: "var(--radius-sm)", background: "var(--bg-card)", color: "var(--text-muted)", fontSize: 12, fontWeight: 600, cursor: "pointer", fontFamily: "'Inter', sans-serif" }}>Clear</button>
          )}
        </div>
      </div>

      <p style={{ fontSize: 13, color: "var(--text-muted)", marginBottom: 16 }}>
        Showing {filteredCloud.length} of {CLOUD_RULES.length} cloud rules
        {cloudSearch && <> matching &quot;<strong style={{ color: "var(--text-primary)" }}>{cloudSearch}</strong>&quot;</>}
      </p>

      <div className="rules-grid">
        {filteredCloud.map((rule) => (
          <RuleCard key={rule.id} rule={rule} isExpanded={expandedRule === rule.id} onToggle={() => setExpandedRule(expandedRule === rule.id ? null : rule.id)} />
        ))}
      </div>

      {filteredCloud.length === 0 && (
        <div className="glass-card" style={{ padding: 48, textAlign: "center" }}>
          <Icon name="search" size={40} style={{ color: "var(--text-muted)", marginBottom: 12 }} />
          <h3 style={{ fontSize: 16, color: "var(--text-secondary)" }}>No cloud rules match your filters</h3>
          <p style={{ color: "var(--text-muted)", fontSize: 13 }}>Try adjusting your search or filter criteria.</p>
        </div>
      )}

      {/* ═══════════════════════════════════════════════════════════════════
           SECTION 2: CONTAINER COMPLIANCE RULES 
          ═══════════════════════════════════════════════════════════════════ */}
      <div style={{
        marginTop: 48,
        paddingTop: 32,
        borderTop: "1px solid var(--border-glass)",
      }}>
        <div className="page-header">
          <h2>Container Compliance Rules</h2>
          <p>CIS Docker Benchmark v1.6.0 and CIS Kubernetes Benchmark v1.8.0 — security controls for containerized workloads</p>
        </div>

        {/* Container Framework Tabs */}
        <div style={{ display: "flex", gap: 10, marginBottom: 12, alignItems: "center", flexWrap: "wrap" }}>
          {CONTAINER_FRAMEWORKS.map((f) => (
            <button key={f} className={`period-btn ${containerFramework === f ? "active" : ""}`} onClick={() => setContainerFramework(f)}
              style={{ display: "flex", alignItems: "center", gap: 6, fontWeight: 600 }}>
              {f === "Docker" && <img src="/logos/docker.svg" alt="Docker" style={{ width: 14, height: 14 }} />}
              {f === "K8s" && <img src="/logos/kubernetes.svg" alt="K8s" style={{ width: 14, height: 14 }} />}
              {f} <span style={{ opacity: 0.7, fontSize: 11 }}>({containerCounts[f]})</span>
            </button>
          ))}
          <span style={{ marginLeft: "auto", fontSize: 12, color: "var(--text-muted)", display: "flex", alignItems: "center", gap: 6 }}>
            <img src="/logos/docker.svg" alt="Docker" style={{ width: 16, height: 16, opacity: 0.7 }} />
            <img src="/logos/kubernetes.svg" alt="K8s" style={{ width: 16, height: 16, opacity: 0.7 }} />
            Controls apply to all container platforms
          </span>
        </div>

        {/* Container Search & Filters */}
        <div className="glass-card" style={{ marginBottom: 20 }}>
          <div className="card-body" style={{ display: "flex", gap: 12, flexWrap: "wrap", alignItems: "center" }}>
            <div className="input-wrapper" style={{ flex: 1, minWidth: 200 }}>
              <span className="input-icon"><Icon name="search" size={16} /></span>
              <input type="text" placeholder="Search container rules by ID, title, description..." value={containerSearch} onChange={(e) => setContainerSearch(e.target.value)} style={{ width: "100%" }} />
            </div>
            <select className="filter-select" value={containerCategory} onChange={(e) => setContainerCategory(e.target.value)}>
              {containerCategories.map((c) => <option key={c} value={c}>{c === "All" ? "All Categories" : c}</option>)}
            </select>
            <select className="filter-select" value={containerSeverity} onChange={(e) => setContainerSeverity(e.target.value)}>
              {SEVERITIES.map((s) => <option key={s} value={s}>{s === "All" ? "All Severities" : s}</option>)}
            </select>
            {containerSearch && (
              <button onClick={() => setContainerSearch("")} style={{ padding: "8px 14px", border: "1px solid var(--border-glass)", borderRadius: "var(--radius-sm)", background: "var(--bg-card)", color: "var(--text-muted)", fontSize: 12, fontWeight: 600, cursor: "pointer", fontFamily: "'Inter', sans-serif" }}>Clear</button>
            )}
          </div>
        </div>

        <p style={{ fontSize: 13, color: "var(--text-muted)", marginBottom: 16 }}>
          Showing {filteredContainer.length} of {CONTAINER_RULES.length} container rules
          {containerSearch && <> matching &quot;<strong style={{ color: "var(--text-primary)" }}>{containerSearch}</strong>&quot;</>}
        </p>

        <div className="rules-grid">
          {filteredContainer.map((rule) => (
            <RuleCard key={rule.id} rule={rule} isExpanded={expandedRule === rule.id} onToggle={() => setExpandedRule(expandedRule === rule.id ? null : rule.id)} />
          ))}
        </div>

        {filteredContainer.length === 0 && (
          <div className="glass-card" style={{ padding: 48, textAlign: "center" }}>
            <Icon name="search" size={40} style={{ color: "var(--text-muted)", marginBottom: 12 }} />
            <h3 style={{ fontSize: 16, color: "var(--text-secondary)" }}>No container rules match your filters</h3>
            <p style={{ color: "var(--text-muted)", fontSize: 13 }}>Try adjusting your search or filter criteria.</p>
          </div>
        )}
      </div>
    </div>
  );
}

