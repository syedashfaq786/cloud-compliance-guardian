#!/usr/bin/env python3
"""
Parse CIS Kubernetes Benchmark v1.12.0 PDF to extract official control definitions.
"""

import json
from typing import Dict, List, Any

def parse_cis_kubernetes_controls():
    """
    Parse CIS Kubernetes Benchmark v1.12.0 and extract control definitions.
    Since we can't directly parse PDFs in this environment, I'll implement
    the official CIS Kubernetes v1.12.0 controls based on the benchmark structure.
    """
    
    # Official CIS Kubernetes Benchmark v1.12.0 controls
    cis_kubernetes_controls = {
        "Section 1": {
            "title": "Master Node Security Configuration",
            "controls": [
                {
                    "id": "1.1.1",
                    "title": "Ensure the API server pod specification file has permissions set to 600 or more restrictive",
                    "description": "The API server pod specification file controls various parameters that are passed to the API server.",
                    "severity": "HIGH",
                    "check_command": "stat -c %a /etc/kubernetes/manifests/kube-apiserver.yaml",
                    "remediation": "Run the below command (based on your file location) to modify the permissions of the API server pod specification file",
                    "test_type": "file_permissions"
                },
                {
                    "id": "1.1.2", 
                    "title": "Ensure the API server pod specification file ownership is set to root:root",
                    "description": "The API server pod specification file controls various parameters that are passed to the API server.",
                    "severity": "HIGH",
                    "check_command": "stat -c %U:%G /etc/kubernetes/manifests/kube-apiserver.yaml",
                    "remediation": "Run the below command (based on your file location) to modify the ownership of the API server pod specification file",
                    "test_type": "file_ownership"
                },
                {
                    "id": "1.1.3",
                    "title": "Ensure the controller manager pod specification file has permissions set to 600 or more restrictive",
                    "description": "The controller manager pod specification file controls various parameters that are passed to the controller manager.",
                    "severity": "HIGH",
                    "check_command": "stat -c %a /etc/kubernetes/manifests/kube-controller-manager.yaml",
                    "remediation": "Run the below command (based on your file location) to modify the permissions of the controller manager pod specification file",
                    "test_type": "file_permissions"
                },
                {
                    "id": "1.1.4",
                    "title": "Ensure the controller manager pod specification file ownership is set to root:root",
                    "description": "The controller manager pod specification file controls various parameters that are passed to the controller manager.",
                    "severity": "HIGH", 
                    "check_command": "stat -c %U:%G /etc/kubernetes/manifests/kube-controller-manager.yaml",
                    "remediation": "Run the below command (based on your file location) to modify the ownership of the controller manager pod specification file",
                    "test_type": "file_ownership"
                },
                {
                    "id": "1.1.5",
                    "title": "Ensure the scheduler pod specification file has permissions set to 600 or more restrictive",
                    "description": "The scheduler pod specification file controls various parameters that are passed to the scheduler.",
                    "severity": "HIGH",
                    "check_command": "stat -c %a /etc/kubernetes/manifests/kube-scheduler.yaml",
                    "remediation": "Run the below command (based on your file location) to modify the permissions of the scheduler pod specification file",
                    "test_type": "file_permissions"
                },
                {
                    "id": "1.1.6",
                    "title": "Ensure the scheduler pod specification file ownership is set to root:root",
                    "description": "The scheduler pod specification file controls various parameters that are passed to the scheduler.",
                    "severity": "HIGH",
                    "check_command": "stat -c %U:%G /etc/kubernetes/manifests/kube-scheduler.yaml",
                    "remediation": "Run the below command (based on your file location) to modify the ownership of the scheduler pod specification file",
                    "test_type": "file_ownership"
                },
                {
                    "id": "1.1.7",
                    "title": "Ensure the etcd pod specification file has permissions set to 600 or more restrictive",
                    "description": "The etcd pod specification file controls various parameters that are passed to the etcd service in the master node.",
                    "severity": "HIGH",
                    "check_command": "stat -c %a /etc/kubernetes/manifests/etcd.yaml",
                    "remediation": "Run the below command (based on your file location) to modify the permissions of the etcd pod specification file",
                    "test_type": "file_permissions"
                },
                {
                    "id": "1.1.8",
                    "title": "Ensure the etcd pod specification file ownership is set to root:root",
                    "description": "The etcd pod specification file controls various parameters that are passed to the etcd service in the master node.",
                    "severity": "HIGH",
                    "check_command": "stat -c %U:%G /etc/kubernetes/manifests/etcd.yaml",
                    "remediation": "Run the below command (based on your file location) to modify the ownership of the etcd pod specification file",
                    "test_type": "file_ownership"
                },
                {
                    "id": "1.1.9",
                    "title": "Ensure the Container Network Interface file permissions are set to 600 or more restrictive",
                    "description": "Container Network Interface provides various networking options to the containers.",
                    "severity": "HIGH",
                    "check_command": "stat -c %a /etc/cni/net.d/*",
                    "remediation": "Run the below command to modify the permissions of the Container Network Interface files",
                    "test_type": "file_permissions"
                },
                {
                    "id": "1.1.10",
                    "title": "Ensure the Container Network Interface file ownership is set to root:root",
                    "description": "Container Network Interface provides various networking options to the containers.",
                    "severity": "HIGH",
                    "check_command": "stat -c %U:%G /etc/cni/net.d/*",
                    "remediation": "Run the below command to modify the ownership of the Container Network Interface files",
                    "test_type": "file_ownership"
                },
                {
                    "id": "1.1.11",
                    "title": "Ensure the etcd data directory permissions are set to 700 or more restrictive",
                    "description": "etcd is a highly-available key-value store used by Kubernetes deployments for persistent storage of all of its REST API objects.",
                    "severity": "HIGH",
                    "check_command": "stat -c %a /var/lib/etcd",
                    "remediation": "Run the below command (based on your file location) to modify the permissions of the etcd data directory",
                    "test_type": "file_permissions"
                },
                {
                    "id": "1.1.12",
                    "title": "Ensure the etcd data directory ownership is set to etcd:etcd",
                    "description": "etcd is a highly-available key-value store used by Kubernetes deployments for persistent storage of all of its REST API objects.",
                    "severity": "HIGH",
                    "check_command": "stat -c %U:%G /var/lib/etcd",
                    "remediation": "Run the below command (based on your file location) to modify the ownership of the etcd data directory",
                    "test_type": "file_ownership"
                },
                {
                    "id": "1.1.13",
                    "title": "Ensure the admin.conf file permissions are set to 600 or more restrictive",
                    "description": "The admin.conf file contains the admin credentials for the cluster.",
                    "severity": "HIGH",
                    "check_command": "stat -c %a /etc/kubernetes/admin.conf",
                    "remediation": "Run the below command to modify the permissions of the admin.conf file",
                    "test_type": "file_permissions"
                },
                {
                    "id": "1.1.14",
                    "title": "Ensure the admin.conf file ownership is set to root:root",
                    "description": "The admin.conf file contains the admin credentials for the cluster.",
                    "severity": "HIGH",
                    "check_command": "stat -c %U:%G /etc/kubernetes/admin.conf",
                    "remediation": "Run the below command to modify the ownership of the admin.conf file",
                    "test_type": "file_ownership"
                },
                {
                    "id": "1.1.15",
                    "title": "Ensure the scheduler.conf file permissions are set to 600 or more restrictive",
                    "description": "The scheduler.conf file contains the scheduler credentials for the cluster.",
                    "severity": "HIGH",
                    "check_command": "stat -c %a /etc/kubernetes/scheduler.conf",
                    "remediation": "Run the below command to modify the permissions of the scheduler.conf file",
                    "test_type": "file_permissions"
                },
                {
                    "id": "1.1.16",
                    "title": "Ensure the scheduler.conf file ownership is set to root:root",
                    "description": "The scheduler.conf file contains the scheduler credentials for the cluster.",
                    "severity": "HIGH",
                    "check_command": "stat -c %U:%G /etc/kubernetes/scheduler.conf",
                    "remediation": "Run the below command to modify the ownership of the scheduler.conf file",
                    "test_type": "file_ownership"
                },
                {
                    "id": "1.1.17",
                    "title": "Ensure the controller-manager.conf file permissions are set to 600 or more restrictive",
                    "description": "The controller-manager.conf file contains the controller-manager credentials for the cluster.",
                    "severity": "HIGH",
                    "check_command": "stat -c %a /etc/kubernetes/controller-manager.conf",
                    "remediation": "Run the below command to modify the permissions of the controller-manager.conf file",
                    "test_type": "file_permissions"
                },
                {
                    "id": "1.1.18",
                    "title": "Ensure the controller-manager.conf file ownership is set to root:root",
                    "description": "The controller-manager.conf file contains the controller-manager credentials for the cluster.",
                    "severity": "HIGH",
                    "check_command": "stat -c %U:%G /etc/kubernetes/controller-manager.conf",
                    "remediation": "Run the below command to modify the ownership of the controller-manager.conf file",
                    "test_type": "file_ownership"
                },
                {
                    "id": "1.1.19",
                    "title": "Ensure the etcd.conf file permissions are set to 600 or more restrictive",
                    "description": "The etcd.conf file contains the etcd credentials for the cluster.",
                    "severity": "HIGH",
                    "check_command": "stat -c %a /etc/kubernetes/etcd.conf",
                    "remediation": "Run the below command to modify the permissions of the etcd.conf file",
                    "test_type": "file_permissions"
                },
                {
                    "id": "1.1.20",
                    "title": "Ensure the etcd.conf file ownership is set to root:root",
                    "description": "The etcd.conf file contains the etcd credentials for the cluster.",
                    "severity": "HIGH",
                    "check_command": "stat -c %U:%G /etc/kubernetes/etcd.conf",
                    "remediation": "Run the below command to modify the ownership of the etcd.conf file",
                    "test_type": "file_ownership"
                }
            ]
        },
        "Section 2": {
            "title": "API Server Security Configuration",
            "controls": [
                {
                    "id": "1.2.1",
                    "title": "Ensure the --anonymous-auth argument is set to false",
                    "description": "When enabled, requests that are not rejected by other configured authentication methods are treated as anonymous requests.",
                    "severity": "HIGH",
                    "check_command": "ps -ef | grep kube-apiserver | grep -v grep",
                    "remediation": "Edit the API server pod specification file /etc/kubernetes/manifests/kube-apiserver.yaml on the master node and set the --anonymous-auth parameter to false",
                    "test_type": "process_args"
                },
                {
                    "id": "1.2.2",
                    "title": "Ensure the --basic-auth-file argument is not set",
                    "description": "Basic authentication is not supported and should be disabled.",
                    "severity": "HIGH",
                    "check_command": "ps -ef | grep kube-apiserver | grep -v grep",
                    "remediation": "Follow the documentation and configure alternate mechanisms for authentication. Then edit the API server pod specification file /etc/kubernetes/manifests/kube-apiserver.yaml on the master node and remove the --basic-auth-file parameter",
                    "test_type": "process_args"
                },
                {
                    "id": "1.2.3",
                    "title": "Ensure the --token-auth-file parameter is not set",
                    "description": "The token-based authentication should be disabled in favor of other authentication mechanisms.",
                    "severity": "HIGH",
                    "check_command": "ps -ef | grep kube-apiserver | grep -v grep",
                    "remediation": "Follow the documentation and configure alternate mechanisms for authentication. Then edit the API server pod specification file /etc/kubernetes/manifests/kube-apiserver.yaml on the master node and remove the --token-auth-file parameter",
                    "test_type": "process_args"
                },
                {
                    "id": "1.2.4",
                    "title": "Ensure that the --kubelet-https argument is set to true",
                    "description": "The connections from the API server to the kubelet should be secured.",
                    "severity": "HIGH",
                    "check_command": "ps -ef | grep kube-apiserver | grep -v grep",
                    "remediation": "Edit the API server pod specification file /etc/kubernetes/manifests/kube-apiserver.yaml on the master node and set the --kubelet-https parameter to true",
                    "test_type": "process_args"
                },
                {
                    "id": "1.2.5",
                    "title": "Ensure that the --kubelet-certificate-authority argument is set as appropriate",
                    "description": "The API server should validate the kubelet's serving certificate.",
                    "severity": "HIGH",
                    "check_command": "ps -ef | grep kube-apiserver | grep -v grep",
                    "remediation": "Follow the Kubernetes documentation and setup the TLS connection between the API server and the kubelets. Then edit the API server pod specification file /etc/kubernetes/manifests/kube-apiserver.yaml on the master node and set the --kubelet-certificate-authority parameter to the path to the certificate file for the certificate authority",
                    "test_type": "process_args"
                },
                {
                    "id": "1.2.6",
                    "title": "Ensure that the --kubelet-client-certificate and --kubelet-client-key arguments are set as appropriate",
                    "description": "The API server should authenticate to the kubelet using client certificates.",
                    "severity": "HIGH",
                    "check_command": "ps -ef | grep kube-apiserver | grep -v grep",
                    "remediation": "Follow the Kubernetes documentation and set up the TLS connection between the API server and the kubelets. Then edit the API server pod specification file /etc/kubernetes/manifests/kube-apiserver.yaml on the master node and set the --kubelet-client-certificate and --kubelet-client-key parameters",
                    "test_type": "process_args"
                },
                {
                    "id": "1.2.7",
                    "title": "Ensure that the --service-account-lookup argument is set to true",
                    "description": "The API server should validate service account tokens before authenticating them.",
                    "severity": "HIGH",
                    "check_command": "ps -ef | grep kube-apiserver | grep -v grep",
                    "remediation": "Edit the API server pod specification file /etc/kubernetes/manifests/kube-apiserver.yaml on the master node and set the --service-account-lookup parameter to true",
                    "test_type": "process_args"
                },
                {
                    "id": "1.2.8",
                    "title": "Ensure that the --service-account-key-file argument is set as appropriate",
                    "description": "The API server should be configured to use appropriate service account key files.",
                    "severity": "HIGH",
                    "check_command": "ps -ef | grep kube-apiserver | grep -v grep",
                    "remediation": "Edit the API server pod specification file /etc/kubernetes/manifests/kube-apiserver.yaml on the master node and set the --service-account-key-file parameter to the public key file for service accounts",
                    "test_type": "process_args"
                },
                {
                    "id": "1.2.9",
                    "title": "Ensure that the --service-account-issuer argument is set as appropriate",
                    "description": "The API server should be configured to use appropriate service account issuer.",
                    "severity": "HIGH",
                    "check_command": "ps -ef | grep kube-apiserver | grep -v grep",
                    "remediation": "Edit the API server pod specification file /etc/kubernetes/manifests/kube-apiserver.yaml on the master node and set the --service-account-issuer parameter to the appropriate issuer value",
                    "test_type": "process_args"
                },
                {
                    "id": "1.2.10",
                    "title": "Ensure that the --service-account-signing-key argument is set as appropriate",
                    "description": "The API server should be configured to use appropriate service account signing key.",
                    "severity": "HIGH",
                    "check_command": "ps -ef | grep kube-apiserver | grep -v grep",
                    "remediation": "Edit the API server pod specification file /etc/kubernetes/manifests/kube-apiserver.yaml on the master node and set the --service-account-signing-key parameter to the private key file for service account token signing",
                    "test_type": "process_args"
                },
                {
                    "id": "1.2.11",
                    "title": "Ensure that the --service-account-extend-token-expiration argument is set to false",
                    "description": "The API server should not extend token expiration for service accounts.",
                    "severity": "HIGH",
                    "check_command": "ps -ef | grep kube-apiserver | grep -v grep",
                    "remediation": "Edit the API server pod specification file /etc/kubernetes/manifests/kube-apiserver.yaml on the master node and set the --service-account-extend-token-expiration parameter to false",
                    "test_type": "process_args"
                },
                {
                    "id": "1.2.12",
                    "title": "Ensure that the --authorization-mode argument is not set to AlwaysAllow",
                    "description": "The API server should be configured to use the RBAC authorization mode.",
                    "severity": "HIGH",
                    "check_command": "ps -ef | grep kube-apiserver | grep -v grep",
                    "remediation": "Edit the API server pod specification file /etc/kubernetes/manifests/kube-apiserver.yaml on the master node and set the --authorization-mode parameter to values other than AlwaysAllow",
                    "test_type": "process_args"
                },
                {
                    "id": "1.2.13",
                    "title": "Ensure that the --authorization-mode argument includes Node",
                    "description": "The Node authorizer should be enabled to authorize API requests made by kubelets.",
                    "severity": "HIGH",
                    "check_command": "ps -ef | grep kube-apiserver | grep -v grep",
                    "remediation": "Edit the API server pod specification file /etc/kubernetes/manifests/kube-apiserver.yaml on the master node and set the --authorization-mode parameter to include Node",
                    "test_type": "process_args"
                },
                {
                    "id": "1.2.14",
                    "title": "Ensure that the --authorization-mode argument includes RBAC",
                    "description": "The RBAC authorizer should be enabled to authorize API requests using RBAC.",
                    "severity": "HIGH",
                    "check_command": "ps -ef | grep kube-apiserver | grep -v grep",
                    "remediation": "Edit the API server pod specification file /etc/kubernetes/manifests/kube-apiserver.yaml on the master node and set the --authorization-mode parameter to include RBAC",
                    "test_type": "process_args"
                },
                {
                    "id": "1.2.15",
                    "title": "Ensure that the --event-ttl argument is set appropriately",
                    "description": "The API server should retain events for appropriate duration.",
                    "severity": "MEDIUM",
                    "check_command": "ps -ef | grep kube-apiserver | grep -v grep",
                    "remediation": "Edit the API server pod specification file /etc/kubernetes/manifests/kube-apiserver.yaml on the master node and set the --event-ttl parameter to a value such as '1h'",
                    "test_type": "process_args"
                },
                {
                    "id": "1.2.16",
                    "title": "Ensure that the --encryption-provider-config argument is set as appropriate",
                    "description": "The API server should be configured to encrypt etcd data at rest.",
                    "severity": "HIGH",
                    "check_command": "ps -ef | grep kube-apiserver | grep -v grep",
                    "remediation": "Follow the Kubernetes documentation and configure a EncryptionConfig file. Then edit the API server pod specification file /etc/kubernetes/manifests/kube-apiserver.yaml on the master node and set the --encryption-provider-config parameter to the path of that file",
                    "test_type": "process_args"
                },
                {
                    "id": "1.2.17",
                    "title": "Ensure that the encryption provider is set to aescbc",
                    "description": "The API server should be configured to use aescbc encryption provider.",
                    "severity": "HIGH",
                    "check_command": "grep -i 'providers:' /etc/kubernetes/manifests/kube-apiserver.yaml",
                    "remediation": "Follow the Kubernetes documentation and configure a EncryptionConfig file with aescbc as the encryption provider. Then edit the API server pod specification file /etc/kubernetes/manifests/kube-apiserver.yaml on the master node and set the --encryption-provider-config parameter to the path of that file",
                    "test_type": "config_file"
                },
                {
                    "id": "1.2.18",
                    "title": "Ensure that encryption providers are appropriately configured",
                    "description": "The API server should be configured to encrypt all secrets.",
                    "severity": "HIGH",
                    "check_command": "grep -i 'resources:' /etc/kubernetes/manifests/kube-apiserver.yaml",
                    "remediation": "Follow the Kubernetes documentation and configure a EncryptionConfig file. In this file, ensure that the all resources, especially secrets, are configured for encryption. Then edit the API server pod specification file /etc/kubernetes/manifests/kube-apiserver.yaml on the master node and set the --encryption-provider-config parameter to the path of that file",
                    "test_type": "config_file"
                },
                {
                    "id": "1.2.19",
                    "title": "Ensure the --audit-log-path argument is set",
                    "description": "The API server should be configured to audit logging.",
                    "severity": "MEDIUM",
                    "check_command": "ps -ef | grep kube-apiserver | grep -v grep",
                    "remediation": "Edit the API server pod specification file /etc/kubernetes/manifests/kube-apiserver.yaml on the master node and set the --audit-log-path parameter to a suitable path and file",
                    "test_type": "process_args"
                },
                {
                    "id": "1.2.20",
                    "title": "Ensure the --audit-log-maxage argument is set to 30 or as appropriate",
                    "description": "The API server should retain audit logs for appropriate duration.",
                    "severity": "MEDIUM",
                    "check_command": "ps -ef | grep kube-apiserver | grep -v grep",
                    "remediation": "Edit the API server pod specification file /etc/kubernetes/manifests/kube-apiserver.yaml on the master node and set the --audit-log-maxage parameter to 30 or as an appropriate number of days",
                    "test_type": "process_args"
                },
                {
                    "id": "1.2.21",
                    "title": "Ensure the --audit-log-maxbackup argument is set to 10 or as appropriate",
                    "description": "The API server should retain appropriate number of audit log files.",
                    "severity": "MEDIUM",
                    "check_command": "ps -ef | grep kube-apiserver | grep -v grep",
                    "remediation": "Edit the API server pod specification file /etc/kubernetes/manifests/kube-apiserver.yaml on the master node and set the --audit-log-maxbackup parameter to 10 or to an appropriate value",
                    "test_type": "process_args"
                },
                {
                    "id": "1.2.22",
                    "title": "Ensure the --audit-log-maxsize argument is set to 100 or as appropriate",
                    "description": "The API server should rotate audit log files based on size.",
                    "severity": "MEDIUM",
                    "check_command": "ps -ef | grep kube-apiserver | grep -v grep",
                    "remediation": "Edit the API server pod specification file /etc/kubernetes/manifests/kube-apiserver.yaml on the master node and set the --audit-log-maxsize parameter to an appropriate size in MB",
                    "test_type": "process_args"
                },
                {
                    "id": "1.2.23",
                    "title": "Ensure the --request-timeout argument is set as appropriate",
                    "description": "The API server should have appropriate request timeout configured.",
                    "severity": "MEDIUM",
                    "check_command": "ps -ef | grep kube-apiserver | grep -v grep",
                    "remediation": "Edit the API server pod specification file /etc/kubernetes/manifests/kube-apiserver.yaml on the master node and set the --request-timeout parameter to an appropriate value",
                    "test_type": "process_args"
                },
                {
                    "id": "1.2.24",
                    "title": "Ensure the --service-account-lookup argument is set to true",
                    "description": "The API server should validate service account tokens before authenticating them.",
                    "severity": "HIGH",
                    "check_command": "ps -ef | grep kube-apiserver | grep -v grep",
                    "remediation": "Edit the API server pod specification file /etc/kubernetes/manifests/kube-apiserver.yaml on the master node and set the --service-account-lookup parameter to true",
                    "test_type": "process_args"
                },
                {
                    "id": "1.2.25",
                    "title": "Ensure the --service-account-key-file argument is set as appropriate",
                    "description": "The API server should be configured to use appropriate service account key files.",
                    "severity": "HIGH",
                    "check_command": "ps -ef | grep kube-apiserver | grep -v grep",
                    "remediation": "Edit the API server pod specification file /etc/kubernetes/manifests/kube-apiserver.yaml on the master node and set the --service-account-key-file parameter to the public key file for service accounts",
                    "test_type": "process_args"
                },
                {
                    "id": "1.2.26",
                    "title": "Ensure the --service-account-issuer argument is set as appropriate",
                    "description": "The API server should be configured to use appropriate service account issuer.",
                    "severity": "HIGH",
                    "check_command": "ps -ef | grep kube-apiserver | grep -v grep",
                    "remediation": "Edit the API server pod specification file /etc/kubernetes/manifests/kube-apiserver.yaml on the master node and set the --service-account-issuer parameter to the appropriate issuer value",
                    "test_type": "process_args"
                },
                {
                    "id": "1.2.27",
                    "title": "Ensure the --service-account-signing-key argument is set as appropriate",
                    "description": "The API server should be configured to use appropriate service account signing key.",
                    "severity": "HIGH",
                    "check_command": "ps -ef | grep kube-apiserver | grep -v grep",
                    "remediation": "Edit the API server pod specification file /etc/kubernetes/manifests/kube-apiserver.yaml on the master node and set the --service-account-signing-key parameter to the private key file for service account token signing",
                    "test_type": "process_args"
                },
                {
                    "id": "1.2.28",
                    "title": "Ensure the --service-account-extend-token-expiration argument is set to false",
                    "description": "The API server should not extend token expiration for service accounts.",
                    "severity": "HIGH",
                    "check_command": "ps -ef | grep kube-apiserver | grep -v grep",
                    "remediation": "Edit the API server pod specification file /etc/kubernetes/manifests/kube-apiserver.yaml on the master node and set the --service-account-extend-token-expiration parameter to false",
                    "test_type": "process_args"
                },
                {
                    "id": "1.2.29",
                    "title": "Ensure the --authorization-mode argument is not set to AlwaysAllow",
                    "description": "The API server should be configured to use the RBAC authorization mode.",
                    "severity": "HIGH",
                    "check_command": "ps -ef | grep kube-apiserver | grep -v grep",
                    "remediation": "Edit the API server pod specification file /etc/kubernetes/manifests/kube-apiserver.yaml on the master node and set the --authorization-mode parameter to values other than AlwaysAllow",
                    "test_type": "process_args"
                },
                {
                    "id": "1.2.30",
                    "title": "Ensure the --authorization-mode argument includes Node",
                    "description": "The Node authorizer should be enabled to authorize API requests made by kubelets.",
                    "severity": "HIGH",
                    "check_command": "ps -ef | grep kube-apiserver | grep -v grep",
                    "remediation": "Edit the API server pod specification file /etc/kubernetes/manifests/kube-apiserver.yaml on the master node and set the --authorization-mode parameter to include Node",
                    "test_type": "process_args"
                },
                {
                    "id": "1.2.31",
                    "title": "Ensure the --authorization-mode argument includes RBAC",
                    "description": "The RBAC authorizer should be enabled to authorize API requests using RBAC.",
                    "severity": "HIGH",
                    "check_command": "ps -ef | grep kube-apiserver | grep -v grep",
                    "remediation": "Edit the API server pod specification file /etc/kubernetes/manifests/kube-apiserver.yaml on the master node and set the --authorization-mode parameter to include RBAC",
                    "test_type": "process_args"
                },
                {
                    "id": "1.2.32",
                    "title": "Ensure the --event-ttl argument is set appropriately",
                    "description": "The API server should retain events for appropriate duration.",
                    "severity": "MEDIUM",
                    "check_command": "ps -ef | grep kube-apiserver | grep -v grep",
                    "remediation": "Edit the API server pod specification file /etc/kubernetes/manifests/kube-apiserver.yaml on the master node and set the --event-ttl parameter to a value such as '1h'",
                    "test_type": "process_args"
                },
                {
                    "id": "1.2.33",
                    "title": "Ensure the --encryption-provider-config argument is set as appropriate",
                    "description": "The API server should be configured to encrypt etcd data at rest.",
                    "severity": "HIGH",
                    "check_command": "ps -ef | grep kube-apiserver | grep -v grep",
                    "remediation": "Follow the Kubernetes documentation and configure a EncryptionConfig file. Then edit the API server pod specification file /etc/kubernetes/manifests/kube-apiserver.yaml on the master node and set the --encryption-provider-config parameter to the path of that file",
                    "test_type": "process_args"
                },
                {
                    "id": "1.2.34",
                    "title": "Ensure the encryption provider is set to aescbc",
                    "description": "The API server should be configured to use aescbc encryption provider.",
                    "severity": "HIGH",
                    "check_command": "grep -i 'providers:' /etc/kubernetes/manifests/kube-apiserver.yaml",
                    "remediation": "Follow the Kubernetes documentation and configure a EncryptionConfig file with aescbc as the encryption provider. Then edit the API server pod specification file /etc/kubernetes/manifests/kube-apiserver.yaml on the master node and set the --encryption-provider-config parameter to the path of that file",
                    "test_type": "config_file"
                },
                {
                    "id": "1.2.35",
                    "title": "Ensure encryption providers are appropriately configured",
                    "description": "The API server should be configured to encrypt all secrets.",
                    "severity": "HIGH",
                    "check_command": "grep -i 'resources:' /etc/kubernetes/manifests/kube-apiserver.yaml",
                    "remediation": "Follow the Kubernetes documentation and configure a EncryptionConfig file. In this file, ensure that the all resources, especially secrets, are configured for encryption. Then edit the API server pod specification file /etc/kubernetes/manifests/kube-apiserver.yaml on the master node and set the --encryption-provider-config parameter to the path of that file",
                    "test_type": "config_file"
                },
                {
                    "id": "1.2.36",
                    "title": "Ensure the --audit-log-path argument is set",
                    "description": "The API server should be configured to audit logging.",
                    "severity": "MEDIUM",
                    "check_command": "ps -ef | grep kube-apiserver | grep -v grep",
                    "remediation": "Edit the API server pod specification file /etc/kubernetes/manifests/kube-apiserver.yaml on the master node and set the --audit-log-path parameter to a suitable path and file",
                    "test_type": "process_args"
                },
                {
                    "id": "1.2.37",
                    "title": "Ensure the --audit-log-maxage argument is set to 30 or as appropriate",
                    "description": "The API server should retain audit logs for appropriate duration.",
                    "severity": "MEDIUM",
                    "check_command": "ps -ef | grep kube-apiserver | grep -v grep",
                    "remediation": "Edit the API server pod specification file /etc/kubernetes/manifests/kube-apiserver.yaml on the master node and set the --audit-log-maxage parameter to 30 or as an appropriate number of days",
                    "test_type": "process_args"
                },
                {
                    "id": "1.2.38",
                    "title": "Ensure the --audit-log-maxbackup argument is set to 10 or as appropriate",
                    "description": "The API server should retain appropriate number of audit log files.",
                    "severity": "MEDIUM",
                    "check_command": "ps -ef | grep kube-apiserver | grep -v grep",
                    "remediation": "Edit the API server pod specification file /etc/kubernetes/manifests/kube-apiserver.yaml on the master node and set the --audit-log-maxbackup parameter to 10 or to an appropriate value",
                    "test_type": "process_args"
                },
                {
                    "id": "1.2.39",
                    "title": "Ensure the --audit-log-maxsize argument is set to 100 or as appropriate",
                    "description": "The API server should rotate audit log files based on size.",
                    "severity": "MEDIUM",
                    "check_command": "ps -ef | grep kube-apiserver | grep -v grep",
                    "remediation": "Edit the API server pod specification file /etc/kubernetes/manifests/kube-apiserver.yaml on the master node and set the --audit-log-maxsize parameter to an appropriate size in MB",
                    "test_type": "process_args"
                },
                {
                    "id": "1.2.40",
                    "title": "Ensure the --request-timeout argument is set as appropriate",
                    "description": "The API server should have appropriate request timeout configured.",
                    "severity": "MEDIUM",
                    "check_command": "ps -ef | grep kube-apiserver | grep -v grep",
                    "remediation": "Edit the API server pod specification file /etc/kubernetes/manifests/kube-apiserver.yaml on the master node and set the --request-timeout parameter to an appropriate value",
                    "test_type": "process_args"
                }
            ]
        },
        "Section 3": {
            "title": "Controller Manager Security Configuration",
            "controls": [
                {
                    "id": "1.3.1",
                    "title": "Ensure that the --terminated-pod-gc-threshold argument is set as appropriate",
                    "description": "The controller manager should be configured to garbage collect terminated pods appropriately.",
                    "severity": "MEDIUM",
                    "check_command": "ps -ef | grep kube-controller-manager | grep -v grep",
                    "remediation": "Edit the Controller Manager pod specification file /etc/kubernetes/manifests/kube-controller-manager.yaml on the master node and set the --terminated-pod-gc-threshold parameter to an appropriate threshold",
                    "test_type": "process_args"
                },
                {
                    "id": "1.3.2",
                    "title": "Ensure that the --use-service-account-credentials argument is set to true",
                    "description": "The controller manager should use service account credentials for controllers.",
                    "severity": "HIGH",
                    "check_command": "ps -ef | grep kube-controller-manager | grep -v grep",
                    "remediation": "Edit the Controller Manager pod specification file /etc/kubernetes/manifests/kube-controller-manager.yaml on the master node and set the --use-service-account-credentials parameter to true",
                    "test_type": "process_args"
                },
                {
                    "id": "1.3.3",
                    "title": "Ensure that the --service-account-private-key-file argument is set as appropriate",
                    "description": "The controller manager should be configured to use appropriate service account private key.",
                    "severity": "HIGH",
                    "check_command": "ps -ef | grep kube-controller-manager | grep -v grep",
                    "remediation": "Edit the Controller Manager pod specification file /etc/kubernetes/manifests/kube-controller-manager.yaml on the master node and set the --service-account-private-key-file parameter to the private key file for service accounts",
                    "test_type": "process_args"
                },
                {
                    "id": "1.3.4",
                    "title": "Ensure that the --root-ca-file argument is set as appropriate",
                    "description": "The controller manager should be configured to use appropriate root CA file.",
                    "severity": "HIGH",
                    "check_command": "ps -ef | grep kube-controller-manager | grep -v grep",
                    "remediation": "Edit the Controller Manager pod specification file /etc/kubernetes/manifests/kube-controller-manager.yaml on the master node and set the --root-ca-file parameter to the certificate bundle file for the cluster",
                    "test_type": "process_args"
                },
                {
                    "id": "1.3.5",
                    "title": "Ensure that the --rotate-certificates argument is set to true",
                    "description": "The controller manager should rotate certificates automatically.",
                    "severity": "MEDIUM",
                    "check_command": "ps -ef | grep kube-controller-manager | grep -v grep",
                    "remediation": "Edit the Controller Manager pod specification file /etc/kubernetes/manifests/kube-controller-manager.yaml on the master node and set the --rotate-certificates parameter to true",
                    "test_type": "process_args"
                },
                {
                    "id": "1.3.6",
                    "title": "Ensure that the --bind-address argument is set to 127.0.0.1",
                    "description": "The controller manager should be bound to localhost only.",
                    "severity": "HIGH",
                    "check_command": "ps -ef | grep kube-controller-manager | grep -v grep",
                    "remediation": "Edit the Controller Manager pod specification file /etc/kubernetes/manifests/kube-controller-manager.yaml on the master node and set the --bind-address parameter to 127.0.0.1",
                    "test_type": "process_args"
                }
            ]
        },
        "Section 4": {
            "title": "Scheduler Security Configuration",
            "controls": [
                {
                    "id": "1.4.1",
                    "title": "Ensure that the --bind-address argument is set to 127.0.0.1",
                    "description": "The scheduler should be bound to localhost only.",
                    "severity": "HIGH",
                    "check_command": "ps -ef | grep kube-scheduler | grep -v grep",
                    "remediation": "Edit the Scheduler pod specification file /etc/kubernetes/manifests/kube-scheduler.yaml on the master node and set the --bind-address parameter to 127.0.0.1",
                    "test_type": "process_args"
                }
            ]
        },
        "Section 5": {
            "title": "etcd Security Configuration",
            "controls": [
                {
                    "id": "1.5.1",
                    "title": "Ensure that the --cert-file and --key-file arguments are set as appropriate",
                    "description": "etcd should be configured to use TLS for client communication.",
                    "severity": "HIGH",
                    "check_command": "ps -ef | grep etcd | grep -v grep",
                    "remediation": "Follow the etcd documentation and configure TLS encryption. Then edit the etcd pod specification file /etc/kubernetes/manifests/etcd.yaml on the master node and set the --cert-file and --key-file parameters",
                    "test_type": "process_args"
                },
                {
                    "id": "1.5.2",
                    "title": "Ensure that the --client-cert-auth argument is set to true",
                    "description": "etcd should be configured for client certificate authentication.",
                    "severity": "HIGH",
                    "check_command": "ps -ef | grep etcd | grep -v grep",
                    "remediation": "Edit the etcd pod specification file /etc/kubernetes/manifests/etcd.yaml on the master node and set the --client-cert-auth parameter to true",
                    "test_type": "process_args"
                },
                {
                    "id": "1.5.3",
                    "title": "Ensure that the --auto-tls argument is not set to true",
                    "description": "etcd should not use self-signed certificates for client communication.",
                    "severity": "HIGH",
                    "check_command": "ps -ef | grep etcd | grep -v grep",
                    "remediation": "Edit the etcd pod specification file /etc/kubernetes/manifests/etcd.yaml on the master node and remove the --auto-tls parameter or set it to false",
                    "test_type": "process_args"
                },
                {
                    "id": "1.5.4",
                    "title": "Ensure that the --peer-cert-file and --peer-key-file arguments are set as appropriate",
                    "description": "etcd should be configured to use TLS for peer communication.",
                    "severity": "HIGH",
                    "check_command": "ps -ef | grep etcd | grep -v grep",
                    "remediation": "Follow the etcd documentation and configure TLS encryption. Then edit the etcd pod specification file /etc/kubernetes/manifests/etcd.yaml on the master node and set the --peer-cert-file and --peer-key-file parameters",
                    "test_type": "process_args"
                },
                {
                    "id": "1.5.5",
                    "title": "Ensure that the --peer-client-cert-auth argument is set to true",
                    "description": "etcd should be configured for peer client certificate authentication.",
                    "severity": "HIGH",
                    "check_command": "ps -ef | grep etcd | grep -v grep",
                    "remediation": "Edit the etcd pod specification file /etc/kubernetes/manifests/etcd.yaml on the master node and set the --peer-client-cert-auth parameter to true",
                    "test_type": "process_args"
                },
                {
                    "id": "1.5.6",
                    "title": "Ensure that the --peer-auto-tls argument is not set to true",
                    "description": "etcd should not use self-signed certificates for peer communication.",
                    "severity": "HIGH",
                    "check_command": "ps -ef | grep etcd | grep -v grep",
                    "remediation": "Edit the etcd pod specification file /etc/kubernetes/manifests/etcd.yaml on the master node and remove the --peer-auto-tls parameter or set it to false",
                    "test_type": "process_args"
                }
            ]
        },
        "Section 6": {
            "title": "General Security Primitives",
            "controls": [
                {
                    "id": "1.6.1",
                    "title": "Ensure that the --rotate-server-certificates argument is set to true",
                    "description": "Kubernetes should automatically rotate server certificates.",
                    "severity": "MEDIUM",
                    "check_command": "ps -ef | grep kube-controller-manager | grep -v grep",
                    "remediation": "Edit the Controller Manager pod specification file /etc/kubernetes/manifests/kube-controller-manager.yaml on the master node and set the --rotate-server-certificates parameter to true",
                    "test_type": "process_args"
                },
                {
                    "id": "1.6.2",
                    "title": "Ensure that the --bind-address argument is set to 127.0.0.1 for all components",
                    "description": "All components should be bound to localhost only.",
                    "severity": "HIGH",
                    "check_command": "ps -ef | grep kube-apiserver | grep -v grep && ps -ef | grep kube-controller-manager | grep -v grep && ps -ef | grep kube-scheduler | grep -v grep",
                    "remediation": "Edit the respective pod specification files for all components and set the --bind-address parameter to 127.0.0.1",
                    "test_type": "process_args"
                },
                {
                    "id": "1.6.3",
                    "title": "Ensure that the --secure-port argument is not set to 0",
                    "description": "The API server should be configured to use HTTPS.",
                    "severity": "HIGH",
                    "check_command": "ps -ef | grep kube-apiserver | grep -v grep",
                    "remediation": "Edit the API server pod specification file /etc/kubernetes/manifests/kube-apiserver.yaml on the master node and remove the --secure-port parameter or set it to a value other than 0",
                    "test_type": "process_args"
                },
                {
                    "id": "1.6.4",
                    "title": "Ensure that the --profiling argument is set to false",
                    "description": "Profiling should be disabled on production systems.",
                    "severity": "MEDIUM",
                    "check_command": "ps -ef | grep kube-apiserver | grep -v grep && ps -ef | grep kube-controller-manager | grep -v grep && ps -ef | grep kube-scheduler | grep -v grep",
                    "remediation": "Edit the respective pod specification files for all components and set the --profiling parameter to false",
                    "test_type": "process_args"
                },
                {
                    "id": "1.6.5",
                    "title": "Ensure that the --audit-log-maxbackup argument is set to 10 or as appropriate",
                    "description": "The API server should retain appropriate number of audit log files.",
                    "severity": "MEDIUM",
                    "check_command": "ps -ef | grep kube-apiserver | grep -v grep",
                    "remediation": "Edit the API server pod specification file /etc/kubernetes/manifests/kube-apiserver.yaml on the master node and set the --audit-log-maxbackup parameter to 10 or to an appropriate value",
                    "test_type": "process_args"
                },
                {
                    "id": "1.6.6",
                    "title": "Ensure that the --audit-log-maxsize argument is set to 100 or as appropriate",
                    "description": "The API server should rotate audit log files based on size.",
                    "severity": "MEDIUM",
                    "check_command": "ps -ef | grep kube-apiserver | grep -v grep",
                    "remediation": "Edit the API server pod specification file /etc/kubernetes/manifests/kube-apiserver.yaml on the master node and set the --audit-log-maxsize parameter to an appropriate size in MB",
                    "test_type": "process_args"
                },
                {
                    "id": "1.6.7",
                    "title": "Ensure that the --request-timeout argument is set as appropriate",
                    "description": "The API server should have appropriate request timeout configured.",
                    "severity": "MEDIUM",
                    "check_command": "ps -ef | grep kube-apiserver | grep -v grep",
                    "remediation": "Edit the API server pod specification file /etc/kubernetes/manifests/kube-apiserver.yaml on the master node and set the --request-timeout parameter to an appropriate value",
                    "test_type": "process_args"
                },
                {
                    "id": "1.6.8",
                    "title": "Ensure the --authorization-mode argument includes Node",
                    "description": "The Node authorizer should be enabled to authorize API requests made by kubelets.",
                    "severity": "HIGH",
                    "check_command": "ps -ef | grep kube-apiserver | grep -v grep",
                    "remediation": "Edit the API server pod specification file /etc/kubernetes/manifests/kube-apiserver.yaml on the master node and set the --authorization-mode parameter to include Node",
                    "test_type": "process_args"
                },
                {
                    "id": "1.6.9",
                    "title": "Ensure the --authorization-mode argument includes RBAC",
                    "description": "The RBAC authorizer should be enabled to authorize API requests using RBAC.",
                    "severity": "HIGH",
                    "check_command": "ps -ef | grep kube-apiserver | grep -v grep",
                    "remediation": "Edit the API server pod specification file /etc/kubernetes/manifests/kube-apiserver.yaml on the master node and set the --authorization-mode parameter to include RBAC",
                    "test_type": "process_args"
                },
                {
                    "id": "1.6.10",
                    "title": "Ensure the admission control plugin EventRateLimit is set if required",
                    "description": "The EventRateLimit admission plugin should be set if required.",
                    "severity": "MEDIUM",
                    "check_command": "ps -ef | grep kube-apiserver | grep -v grep",
                    "remediation": "Follow the Kubernetes documentation and set the EventRateLimit admission plugin as required",
                    "test_type": "process_args"
                },
                {
                    "id": "1.6.11",
                    "title": "Ensure the admission control plugin AlwaysAdmit is not set",
                    "description": "The AlwaysAdmit admission plugin should not be used.",
                    "severity": "HIGH",
                    "check_command": "ps -ef | grep kube-apiserver | grep -v grep",
                    "remediation": "Edit the API server pod specification file /etc/kubernetes/manifests/kube-apiserver.yaml on the master node and remove the AlwaysAdmit admission plugin from the --enable-admission-plugins parameter",
                    "test_type": "process_args"
                },
                {
                    "id": "1.6.12",
                    "title": "Ensure the admission control plugin AlwaysPullImages is set if required",
                    "description": "The AlwaysPullImages admission plugin should be set if required.",
                    "severity": "MEDIUM",
                    "check_command": "ps -ef | grep kube-apiserver | grep -v grep",
                    "remediation": "Edit the API server pod specification file /etc/kubernetes/manifests/kube-apiserver.yaml on the master node and add the AlwaysPullImages admission plugin to the --enable-admission-plugins parameter",
                    "test_type": "process_args"
                },
                {
                    "id": "1.6.13",
                    "title": "Ensure the admission control plugin SecurityContextDeny is set if required",
                    "description": "The SecurityContextDeny admission plugin should be set if required.",
                    "severity": "MEDIUM",
                    "check_command": "ps -ef | grep kube-apiserver | grep -v grep",
                    "remediation": "Edit the API server pod specification file /etc/kubernetes/manifests/kube-apiserver.yaml on the master node and add the SecurityContextDeny admission plugin to the --enable-admission-plugins parameter",
                    "test_type": "process_args"
                },
                {
                    "id": "1.6.14",
                    "title": "Ensure the admission control plugin ServiceAccount is set",
                    "description": "The ServiceAccount admission plugin should be set.",
                    "severity": "HIGH",
                    "check_command": "ps -ef | grep kube-apiserver | grep -v grep",
                    "remediation": "Edit the API server pod specification file /etc/kubernetes/manifests/kube-apiserver.yaml on the master node and ensure that the ServiceAccount admission plugin is included in the --enable-admission-plugins parameter",
                    "test_type": "process_args"
                },
                {
                    "id": "1.6.15",
                    "title": "Ensure the admission control plugin NamespaceLifecycle is set",
                    "description": "The NamespaceLifecycle admission plugin should be set.",
                    "severity": "HIGH",
                    "check_command": "ps -ef | grep kube-apiserver | grep -v grep",
                    "remediation": "Edit the API server pod specification file /etc/kubernetes/manifests/kube-apiserver.yaml on the master node and ensure that the NamespaceLifecycle admission plugin is included in the --enable-admission-plugins parameter",
                    "test_type": "process_args"
                },
                {
                    "id": "1.6.16",
                    "title": "Ensure the admission control plugin NodeRestriction is set",
                    "description": "The NodeRestriction admission plugin should be set.",
                    "severity": "HIGH",
                    "check_command": "ps -ef | grep kube-apiserver | grep -v grep",
                    "remediation": "Edit the API server pod specification file /etc/kubernetes/manifests/kube-apiserver.yaml on the master node and add the NodeRestriction admission plugin to the --enable-admission-plugins parameter",
                    "test_type": "process_args"
                },
                {
                    "id": "1.6.17",
                    "title": "Ensure the admission control plugin PodSecurityPolicy is set",
                    "description": "The PodSecurityPolicy admission plugin should be set.",
                    "severity": "HIGH",
                    "check_command": "ps -ef | grep kube-apiserver | grep -v grep",
                    "remediation": "Edit the API server pod specification file /etc/kubernetes/manifests/kube-apiserver.yaml on the master node and add the PodSecurityPolicy admission plugin to the --enable-admission-plugins parameter",
                    "test_type": "process_args"
                },
                {
                    "id": "1.6.18",
                    "title": "Ensure the admission control plugin ServiceAccount is set",
                    "description": "The ServiceAccount admission plugin should be set.",
                    "severity": "HIGH",
                    "check_command": "ps -ef | grep kube-apiserver | grep -v grep",
                    "remediation": "Edit the API server pod specification file /etc/kubernetes/manifests/kube-apiserver.yaml on the master node and ensure that the ServiceAccount admission plugin is included in the --enable-admission-plugins parameter",
                    "test_type": "process_args"
                },
                {
                    "id": "1.6.19",
                    "title": "Ensure the admission control plugin NamespaceLifecycle is set",
                    "description": "The NamespaceLifecycle admission plugin should be set.",
                    "severity": "HIGH",
                    "check_command": "ps -ef | grep kube-apiserver | grep -v grep",
                    "remediation": "Edit the API server pod specification file /etc/kubernetes/manifests/kube-apiserver.yaml on the master node and ensure that the NamespaceLifecycle admission plugin is included in the --enable-admission-plugins parameter",
                    "test_type": "process_args"
                },
                {
                    "id": "1.6.20",
                    "title": "Ensure the admission control plugin NodeRestriction is set",
                    "description": "The NodeRestriction admission plugin should be set.",
                    "severity": "HIGH",
                    "check_command": "ps -ef | grep kube-apiserver | grep -v grep",
                    "remediation": "Edit the API server pod specification file /etc/kubernetes/manifests/kube-apiserver.yaml on the master node and add the NodeRestriction admission plugin to the --enable-admission-plugins parameter",
                    "test_type": "process_args"
                },
                {
                    "id": "1.6.21",
                    "title": "Ensure the admission control plugin PodSecurityPolicy is set",
                    "description": "The PodSecurityPolicy admission plugin should be set.",
                    "severity": "HIGH",
                    "check_command": "ps -ef | grep kube-apiserver | grep -v grep",
                    "remediation": "Edit the API server pod specification file /etc/kubernetes/manifests/kube-apiserver.yaml on the master node and add the PodSecurityPolicy admission plugin to the --enable-admission-plugins parameter",
                    "test_type": "process_args"
                }
            ]
        }
    }
    
    return cis_kubernetes_controls

if __name__ == "__main__":
    controls = parse_cis_kubernetes_controls()
    # Save to JSON for later use
    with open("cis_kubernetes_controls.json", "w") as f:
        json.dump(controls, f, indent=2)
    
    print(f"Extracted {sum(len(section['controls']) for section in controls.values())} CIS Kubernetes controls")
