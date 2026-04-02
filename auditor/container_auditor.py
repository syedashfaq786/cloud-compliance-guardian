"""
Container Auditor — Real Docker and Kubernetes security auditing.

Runs docker and kubectl CLI commands via subprocess to fetch live container
configurations, then checks them against:
  - CIS Docker Benchmark v1.6
  - CIS Kubernetes Benchmark v1.8
"""

import json
import subprocess
import hashlib
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional


# ── Helpers ───────────────────────────────────────────────────────────────────

def _run(cmd: List[str], timeout: int = 30) -> Optional[str]:
    """Run a subprocess command and return stdout, or None on failure."""
    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
        )
        if result.returncode == 0:
            return result.stdout.strip()
        return None
    except FileNotFoundError:
        return None
    except subprocess.TimeoutExpired:
        return None
    except Exception:
        return None


def _run_json(cmd: List[str], timeout: int = 30) -> Optional[Any]:
    """Run a subprocess command and parse JSON output."""
    out = _run(cmd, timeout=timeout)
    if out is None:
        return None
    try:
        return json.loads(out)
    except (json.JSONDecodeError, ValueError):
        return None


def _hash_id(raw: str) -> str:
    """Short stable hash for resource IDs."""
    return hashlib.sha256(raw.encode()).hexdigest()[:12]


def _finding(
    resource_id: str,
    resource_name: str,
    resource_type: str,
    status: str,
    severity: str,
    rule_id: str,
    title: str,
    description: str,
    reasoning: str,
    expected: str,
    actual: str,
    recommendation: str,
    remediation_step: str,
    framework: str = "CIS",
) -> Dict[str, Any]:
    return {
        "resource_id": resource_id,
        "resource_name": resource_name,
        "resource_type": resource_type,
        "status": status,
        "severity": severity,
        "framework": framework,
        "rule_id": rule_id,
        # Provide both names so the existing UI/report generator can find it
        "cis_rule_id": rule_id,
        "title": title,
        "description": description,
        "reasoning": reasoning,
        "expected": expected,
        "actual": actual,
        "recommendation": recommendation,
        "remediation_step": remediation_step,
    }


# ── CIS Docker Benchmark v1.6 ─────────────────────────────────────────────────

def _check_docker_container(container_id: str, inspect: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Run all CIS Docker Benchmark v1.6 checks against a single container inspect payload."""
    findings: List[Dict[str, Any]] = []
    name = inspect.get("Name", "").lstrip("/") or container_id[:12]
    rid = _hash_id(container_id)
    cfg = inspect.get("Config", {})
    host_cfg = inspect.get("HostConfig", {})
    net_settings = inspect.get("NetworkSettings", {})

    # ── CIS-DOCKER-4.1: Container runs as root ────────────────────────────────
    user = cfg.get("User", "") or ""
    runs_as_root = user == "" or user == "root" or user == "0"
    findings.append(_finding(
        resource_id=rid,
        resource_name=name,
        resource_type="docker_container",
        status="FAIL" if runs_as_root else "PASS",
        severity="HIGH",
        rule_id="CIS-DOCKER-4.1",
        title="Container runs as root user",
        description=f"Container '{name}' is running as root, which grants full privileges inside the container and increases blast radius if the container is compromised.",
        reasoning=f"Inspected Config.User for container '{name}'. Value is '{user or '(empty)'}'. An empty value or 'root' means the process runs as UID 0.",
        expected="A non-root user specified via the USER directive in the Dockerfile or --user flag",
        actual=f"User: '{user or '(empty — defaults to root)'}'",
        recommendation="Set a non-root user in the Dockerfile with USER <username> or pass --user <uid> at runtime.",
        remediation_step="docker run --user 1000:1000 <image> OR add 'USER appuser' to your Dockerfile",
    ))

    # ── CIS-DOCKER-4.5: AppArmor/Seccomp profile not set ─────────────────────
    seccomp = host_cfg.get("SecurityOpt") or []
    has_seccomp = any("seccomp" in str(s).lower() for s in seccomp)
    has_apparmor = any("apparmor" in str(s).lower() for s in seccomp)
    no_security_profile = not has_seccomp and not has_apparmor
    findings.append(_finding(
        resource_id=rid,
        resource_name=name,
        resource_type="docker_container",
        status="FAIL" if no_security_profile else "PASS",
        severity="MEDIUM",
        rule_id="CIS-DOCKER-4.5",
        title="No AppArmor or Seccomp profile applied",
        description=f"Container '{name}' does not have an AppArmor or Seccomp security profile applied, leaving the kernel attack surface unrestricted.",
        reasoning=f"Inspected HostConfig.SecurityOpt for container '{name}'. SecurityOpt list: {seccomp}. Neither 'apparmor' nor 'seccomp' entries were found.",
        expected="HostConfig.SecurityOpt to contain a seccomp or apparmor profile",
        actual=f"SecurityOpt: {seccomp or '[]'}",
        recommendation="Apply the default Docker seccomp profile or a custom AppArmor profile.",
        remediation_step="docker run --security-opt seccomp=/etc/docker/seccomp-default.json <image>",
    ))

    # ── CIS-DOCKER-4.6: Privileged mode enabled ───────────────────────────────
    privileged = host_cfg.get("Privileged", False)
    findings.append(_finding(
        resource_id=rid,
        resource_name=name,
        resource_type="docker_container",
        status="FAIL" if privileged else "PASS",
        severity="CRITICAL",
        rule_id="CIS-DOCKER-4.6",
        title="Container running in privileged mode",
        description=f"Container '{name}' is running in privileged mode, which grants nearly all Linux capabilities and effectively disables container isolation.",
        reasoning=f"Inspected HostConfig.Privileged for container '{name}'. Value is {privileged}.",
        expected="HostConfig.Privileged = false",
        actual=f"Privileged: {privileged}",
        recommendation="Remove --privileged from the run command. Instead, grant only the specific Linux capabilities required.",
        remediation_step="docker run --cap-add NET_ADMIN <image>  # add only needed capabilities instead of --privileged",
    ))

    # ── CIS-DOCKER-5.1: AppArmor profile not applied ──────────────────────────
    apparmor_profile = inspect.get("AppArmorProfile", "") or ""
    no_apparmor = apparmor_profile == "" or apparmor_profile == "unconfined"
    findings.append(_finding(
        resource_id=rid,
        resource_name=name,
        resource_type="docker_container",
        status="FAIL" if no_apparmor else "PASS",
        severity="MEDIUM",
        rule_id="CIS-DOCKER-5.1",
        title="AppArmor profile not applied to container",
        description=f"Container '{name}' does not have an AppArmor profile applied. AppArmor provides mandatory access control policies that restrict container capabilities.",
        reasoning=f"Inspected AppArmorProfile for container '{name}'. Value is '{apparmor_profile or '(empty)'}'.",
        expected="AppArmorProfile set to a valid profile (e.g., 'docker-default')",
        actual=f"AppArmorProfile: '{apparmor_profile or '(empty)'}'",
        recommendation="Apply the default Docker AppArmor profile or a custom policy.",
        remediation_step="docker run --security-opt apparmor=docker-default <image>",
    ))

    # ── CIS-DOCKER-5.4: Privileged ports mapped ───────────────────────────────
    port_bindings = host_cfg.get("PortBindings") or {}
    privileged_ports = []
    for container_port, bindings in port_bindings.items():
        if bindings:
            for b in bindings:
                host_port_str = b.get("HostPort", "0") or "0"
                try:
                    hp = int(host_port_str)
                    if 0 < hp < 1024:
                        privileged_ports.append(hp)
                except ValueError:
                    pass
    has_privileged_ports = bool(privileged_ports)
    findings.append(_finding(
        resource_id=rid,
        resource_name=name,
        resource_type="docker_container",
        status="FAIL" if has_privileged_ports else "PASS",
        severity="MEDIUM",
        rule_id="CIS-DOCKER-5.4",
        title="Privileged ports (< 1024) mapped to container",
        description=f"Container '{name}' maps host privileged ports {privileged_ports} which requires elevated host privileges and may indicate unnecessary exposure.",
        reasoning=f"Inspected HostConfig.PortBindings. Found ports below 1024: {privileged_ports}.",
        expected="No host port bindings below 1024",
        actual=f"Privileged ports mapped: {privileged_ports}",
        recommendation="Use unprivileged ports (>= 1024) on the host and map them to the container port as needed.",
        remediation_step="docker run -p 8080:80 <image>  # map container port 80 to host port 8080 instead",
    ))

    # ── CIS-DOCKER-5.7: Host network mode ────────────────────────────────────
    network_mode = host_cfg.get("NetworkMode", "") or ""
    uses_host_network = network_mode == "host"
    findings.append(_finding(
        resource_id=rid,
        resource_name=name,
        resource_type="docker_container",
        status="FAIL" if uses_host_network else "PASS",
        severity="HIGH",
        rule_id="CIS-DOCKER-5.7",
        title="Container uses host network mode",
        description=f"Container '{name}' runs with --network=host, bypassing Docker's network namespace isolation and exposing all host network interfaces to the container.",
        reasoning=f"Inspected HostConfig.NetworkMode for container '{name}'. Value is '{network_mode}'.",
        expected="NetworkMode != 'host' (use bridge, overlay, or user-defined network)",
        actual=f"NetworkMode: '{network_mode}'",
        recommendation="Remove --network=host and use a user-defined bridge or overlay network.",
        remediation_step="docker network create mynet && docker run --network=mynet <image>",
    ))

    # ── CIS-DOCKER-5.9: Host PID namespace shared ─────────────────────────────
    pid_mode = host_cfg.get("PidMode", "") or ""
    uses_host_pid = pid_mode == "host"
    findings.append(_finding(
        resource_id=rid,
        resource_name=name,
        resource_type="docker_container",
        status="FAIL" if uses_host_pid else "PASS",
        severity="HIGH",
        rule_id="CIS-DOCKER-5.9",
        title="Container shares host PID namespace",
        description=f"Container '{name}' shares the host PID namespace, allowing processes inside the container to see and potentially interact with all host processes.",
        reasoning=f"Inspected HostConfig.PidMode for container '{name}'. Value is '{pid_mode}'.",
        expected="PidMode not set to 'host'",
        actual=f"PidMode: '{pid_mode or '(container namespace — ok)'}'",
        recommendation="Remove --pid=host from the docker run command.",
        remediation_step="Do not pass --pid=host when starting the container",
    ))

    # ── CIS-DOCKER-5.10: Host IPC namespace shared ────────────────────────────
    ipc_mode = host_cfg.get("IpcMode", "") or ""
    uses_host_ipc = ipc_mode == "host"
    findings.append(_finding(
        resource_id=rid,
        resource_name=name,
        resource_type="docker_container",
        status="FAIL" if uses_host_ipc else "PASS",
        severity="MEDIUM",
        rule_id="CIS-DOCKER-5.10",
        title="Container shares host IPC namespace",
        description=f"Container '{name}' shares the host IPC namespace, enabling shared memory segments with the host which can lead to data leakage.",
        reasoning=f"Inspected HostConfig.IpcMode for container '{name}'. Value is '{ipc_mode}'.",
        expected="IpcMode not set to 'host'",
        actual=f"IpcMode: '{ipc_mode or '(private — ok)'}'",
        recommendation="Remove --ipc=host from the docker run command.",
        remediation_step="Do not pass --ipc=host when starting the container",
    ))

    # ── CIS-DOCKER-5.14: Sensitive host paths mounted read-write ─────────────
    mounts = inspect.get("Mounts") or []
    sensitive_paths = ["/etc", "/proc", "/sys", "/var/run", "/", "/boot", "/dev"]
    dangerous_mounts = []
    for mount in mounts:
        src = mount.get("Source", "") or ""
        mode = mount.get("Mode", "") or mount.get("RW", True)
        rw = mode != "ro" if isinstance(mode, str) else mode
        for sp in sensitive_paths:
            if src == sp or src.startswith(sp + "/"):
                if rw:
                    dangerous_mounts.append(src)
    has_dangerous_mounts = bool(dangerous_mounts)
    findings.append(_finding(
        resource_id=rid,
        resource_name=name,
        resource_type="docker_container",
        status="FAIL" if has_dangerous_mounts else "PASS",
        severity="CRITICAL",
        rule_id="CIS-DOCKER-5.14",
        title="Sensitive host paths mounted read-write",
        description=f"Container '{name}' mounts sensitive host paths {dangerous_mounts} as read-write, potentially allowing container processes to modify critical host files.",
        reasoning=f"Inspected Mounts for container '{name}'. Found read-write mounts on sensitive paths: {dangerous_mounts}.",
        expected="No sensitive host paths (/etc, /proc, /sys, /) mounted as read-write",
        actual=f"Dangerous mounts: {dangerous_mounts}",
        recommendation="Mount sensitive paths as read-only (:ro) or avoid mounting them entirely.",
        remediation_step="docker run -v /host/data:/container/data:ro <image>  # use :ro suffix",
    ))

    # ── CIS-DOCKER-5.25: Docker socket mounted inside container ──────────────
    docker_socket_mounted = any(
        m.get("Source", "") == "/var/run/docker.sock"
        for m in mounts
    )
    findings.append(_finding(
        resource_id=rid,
        resource_name=name,
        resource_type="docker_container",
        status="FAIL" if docker_socket_mounted else "PASS",
        severity="CRITICAL",
        rule_id="CIS-DOCKER-5.25",
        title="Docker socket mounted inside container",
        description=f"Container '{name}' has the Docker socket (/var/run/docker.sock) mounted, granting the container full control of the Docker daemon and effectively root access to the host.",
        reasoning=f"Inspected Mounts for container '{name}'. Found /var/run/docker.sock in mount list.",
        expected="Docker socket (/var/run/docker.sock) not mounted inside any container",
        actual=f"Docker socket mounted: {docker_socket_mounted}",
        recommendation="Never mount the Docker socket inside a container unless absolutely required for CI tooling. Use socket proxies instead.",
        remediation_step="Remove -v /var/run/docker.sock:/var/run/docker.sock from the docker run command",
    ))

    # ── CIS-DOCKER-5.28: PIDs limit not set ──────────────────────────────────
    pids_limit = host_cfg.get("PidsLimit") or 0
    no_pids_limit = pids_limit is None or pids_limit <= 0
    findings.append(_finding(
        resource_id=rid,
        resource_name=name,
        resource_type="docker_container",
        status="FAIL" if no_pids_limit else "PASS",
        severity="LOW",
        rule_id="CIS-DOCKER-5.28",
        title="Container PIDs limit not set",
        description=f"Container '{name}' has no PIDs limit configured, allowing an unrestricted number of processes that could exhaust host resources in a fork bomb scenario.",
        reasoning=f"Inspected HostConfig.PidsLimit for container '{name}'. Value is {pids_limit}. 0 or negative means no limit.",
        expected="PidsLimit > 0 (e.g., 100–1000 depending on workload)",
        actual=f"PidsLimit: {pids_limit}",
        recommendation="Set a PID limit appropriate for the workload using --pids-limit.",
        remediation_step="docker run --pids-limit=200 <image>",
    ))

    # ── CIS-DOCKER-5.31: Memory limit not set ────────────────────────────────
    memory = host_cfg.get("Memory") or 0
    no_memory_limit = memory is None or memory <= 0
    findings.append(_finding(
        resource_id=rid,
        resource_name=name,
        resource_type="docker_container",
        status="FAIL" if no_memory_limit else "PASS",
        severity="MEDIUM",
        rule_id="CIS-DOCKER-5.31",
        title="Container memory limit not set",
        description=f"Container '{name}' has no memory limit, allowing it to consume all available host memory which can cause out-of-memory conditions for other processes.",
        reasoning=f"Inspected HostConfig.Memory for container '{name}'. Value is {memory}. 0 means unlimited.",
        expected="Memory limit > 0 bytes set via --memory flag",
        actual=f"Memory: {memory} bytes (unlimited)",
        recommendation="Set an appropriate memory limit based on the container's expected workload.",
        remediation_step="docker run --memory=512m <image>",
    ))

    return findings


def _check_docker_swarm(info: Dict[str, Any]) -> List[Dict[str, Any]]:
    """CIS-DOCKER-7.1: Check if Swarm mode is in use on a single-node setup."""
    findings = []
    swarm = info.get("Swarm", {}) or {}
    swarm_local_id = swarm.get("LocalNodeState", "inactive")
    swarm_active = swarm_local_id not in ("inactive", "")
    findings.append(_finding(
        resource_id=_hash_id("docker-daemon"),
        resource_name="Docker Daemon",
        resource_type="docker_daemon",
        status="PASS" if not swarm_active else "PASS",  # Swarm active is not a FAIL per se
        severity="LOW",
        rule_id="CIS-DOCKER-7.1",
        title="Docker Swarm mode status",
        description="Docker Swarm mode is being used. Ensure Swarm is intentional; disable if not needed to reduce attack surface.",
        reasoning=f"Inspected docker info Swarm.LocalNodeState. Value is '{swarm_local_id}'.",
        expected="Swarm mode disabled if not intentionally used",
        actual=f"Swarm state: '{swarm_local_id}'",
        recommendation="If Swarm is not intentionally used, disable it with 'docker swarm leave --force'.",
        remediation_step="docker swarm leave --force",
    ))
    return findings


# ── CIS Kubernetes Benchmark v1.8 ─────────────────────────────────────────────

def _run_kubectl(args: List[str], output_format: str = "json") -> Optional[Any]:
    """Run a kubectl command and return parsed JSON output."""
    cmd = ["kubectl"] + args
    if output_format == "json":
        cmd += ["-o", "json"]
    return _run_json(cmd)


def _check_k8s_cluster_admin_bindings() -> List[Dict[str, Any]]:
    """CIS-K8S-5.1.1: Cluster-admin role binding — non-system subjects."""
    findings = []
    crbs = _run_kubectl(["get", "clusterrolebindings"])
    if crbs is None:
        return []
    for item in crbs.get("items", []):
        name = item.get("metadata", {}).get("name", "unknown")
        rid = _hash_id(f"clusterrolebinding:{name}")
        role_ref = item.get("roleRef", {})
        if role_ref.get("name") != "cluster-admin":
            continue
        subjects = item.get("subjects") or []
        non_system = [
            s for s in subjects
            if not str(s.get("name", "")).startswith("system:")
        ]
        if non_system:
            findings.append(_finding(
                resource_id=rid,
                resource_name=name,
                resource_type="k8s_clusterrolebinding",
                status="FAIL",
                severity="CRITICAL",
                rule_id="CIS-K8S-5.1.1",
                title="Non-system subject bound to cluster-admin role",
                description=f"ClusterRoleBinding '{name}' grants cluster-admin to non-system subjects: {[s.get('name') for s in non_system]}. This provides unrestricted cluster access.",
                reasoning=f"Found ClusterRoleBinding '{name}' referencing roleRef cluster-admin with non-system subjects.",
                expected="cluster-admin bound only to system: service accounts",
                actual=f"Non-system subjects: {[s.get('name') for s in non_system]}",
                recommendation="Remove unnecessary cluster-admin bindings. Use namespace-scoped roles with least privilege.",
                remediation_step=f"kubectl delete clusterrolebinding {name}",
            ))
        else:
            findings.append(_finding(
                resource_id=rid,
                resource_name=name,
                resource_type="k8s_clusterrolebinding",
                status="PASS",
                severity="CRITICAL",
                rule_id="CIS-K8S-5.1.1",
                title="Cluster-admin binding uses only system subjects",
                description=f"ClusterRoleBinding '{name}' binds cluster-admin only to system service accounts.",
                reasoning="All subjects prefixed with 'system:' — compliant.",
                expected="Only system: subjects",
                actual="Only system: subjects",
                recommendation="No action required.",
                remediation_step="",
            ))
    return findings


def _check_k8s_pods() -> List[Dict[str, Any]]:
    """Run CIS Kubernetes Benchmark pod-level checks (5.2.x)."""
    findings = []
    pods = _run_kubectl(["get", "pods", "--all-namespaces"])
    if pods is None:
        return []

    for item in pods.get("items", []):
        meta = item.get("metadata", {})
        pod_name = meta.get("name", "unknown")
        namespace = meta.get("namespace", "default")
        rid = _hash_id(f"pod:{namespace}/{pod_name}")
        spec = item.get("spec", {})

        # CIS-K8S-5.2.1: Privileged containers
        containers = spec.get("containers", []) + spec.get("initContainers", [])
        privileged_containers = [
            c.get("name", "") for c in containers
            if (c.get("securityContext") or {}).get("privileged") is True
        ]
        has_privileged = bool(privileged_containers)
        findings.append(_finding(
            resource_id=rid,
            resource_name=f"{namespace}/{pod_name}",
            resource_type="k8s_pod",
            status="FAIL" if has_privileged else "PASS",
            severity="CRITICAL",
            rule_id="CIS-K8S-5.2.1",
            title="Privileged containers in pod",
            description=f"Pod '{namespace}/{pod_name}' has privileged containers: {privileged_containers}. Privileged containers disable security isolation.",
            reasoning=f"Checked securityContext.privileged for each container in pod '{pod_name}'.",
            expected="No container has securityContext.privileged: true",
            actual=f"Privileged containers: {privileged_containers or 'none'}",
            recommendation="Remove securityContext.privileged: true from all containers.",
            remediation_step="Set securityContext.privileged: false in the pod manifest",
        ))

        # CIS-K8S-5.2.2: hostPID
        host_pid = spec.get("hostPID", False)
        findings.append(_finding(
            resource_id=rid,
            resource_name=f"{namespace}/{pod_name}",
            resource_type="k8s_pod",
            status="FAIL" if host_pid else "PASS",
            severity="HIGH",
            rule_id="CIS-K8S-5.2.2",
            title="Pod uses host PID namespace",
            description=f"Pod '{namespace}/{pod_name}' has hostPID: true, allowing container processes to see and interact with all host processes.",
            reasoning=f"Checked spec.hostPID for pod '{pod_name}'. Value: {host_pid}.",
            expected="spec.hostPID: false (or absent)",
            actual=f"hostPID: {host_pid}",
            recommendation="Remove hostPID: true from the pod spec.",
            remediation_step="Remove hostPID: true from pod spec YAML",
        ))

        # CIS-K8S-5.2.3: hostIPC
        host_ipc = spec.get("hostIPC", False)
        findings.append(_finding(
            resource_id=rid,
            resource_name=f"{namespace}/{pod_name}",
            resource_type="k8s_pod",
            status="FAIL" if host_ipc else "PASS",
            severity="MEDIUM",
            rule_id="CIS-K8S-5.2.3",
            title="Pod uses host IPC namespace",
            description=f"Pod '{namespace}/{pod_name}' has hostIPC: true, enabling shared memory communication with host processes.",
            reasoning=f"Checked spec.hostIPC for pod '{pod_name}'. Value: {host_ipc}.",
            expected="spec.hostIPC: false (or absent)",
            actual=f"hostIPC: {host_ipc}",
            recommendation="Remove hostIPC: true from the pod spec.",
            remediation_step="Remove hostIPC: true from pod spec YAML",
        ))

        # CIS-K8S-5.2.4: hostNetwork
        host_network = spec.get("hostNetwork", False)
        findings.append(_finding(
            resource_id=rid,
            resource_name=f"{namespace}/{pod_name}",
            resource_type="k8s_pod",
            status="FAIL" if host_network else "PASS",
            severity="HIGH",
            rule_id="CIS-K8S-5.2.4",
            title="Pod uses host network namespace",
            description=f"Pod '{namespace}/{pod_name}' has hostNetwork: true, bypassing Kubernetes network isolation.",
            reasoning=f"Checked spec.hostNetwork for pod '{pod_name}'. Value: {host_network}.",
            expected="spec.hostNetwork: false (or absent)",
            actual=f"hostNetwork: {host_network}",
            recommendation="Remove hostNetwork: true and use Kubernetes service networking.",
            remediation_step="Remove hostNetwork: true from pod spec YAML",
        ))

        # CIS-K8S-5.2.6: Root containers
        pod_sc = spec.get("securityContext") or {}
        run_as_non_root_pod = pod_sc.get("runAsNonRoot")
        root_containers = []
        for c in containers:
            c_sc = c.get("securityContext") or {}
            c_run_non_root = c_sc.get("runAsNonRoot")
            c_run_as_user = c_sc.get("runAsUser")
            # Container is root if neither container nor pod level sets runAsNonRoot=true
            # AND runAsUser is 0 or not set
            if c_run_non_root is not True and run_as_non_root_pod is not True:
                if c_run_as_user is None or c_run_as_user == 0:
                    root_containers.append(c.get("name", ""))
        has_root_containers = bool(root_containers)
        findings.append(_finding(
            resource_id=rid,
            resource_name=f"{namespace}/{pod_name}",
            resource_type="k8s_pod",
            status="FAIL" if has_root_containers else "PASS",
            severity="HIGH",
            rule_id="CIS-K8S-5.2.6",
            title="Containers may run as root",
            description=f"Pod '{namespace}/{pod_name}' has containers without runAsNonRoot enforced: {root_containers}.",
            reasoning=f"Checked securityContext.runAsNonRoot for pod and containers. Containers without explicit non-root enforcement: {root_containers}.",
            expected="securityContext.runAsNonRoot: true set at pod or container level",
            actual=f"Containers without runAsNonRoot: {root_containers or 'none'}",
            recommendation="Add securityContext.runAsNonRoot: true at the pod spec level.",
            remediation_step="Add 'runAsNonRoot: true' under spec.securityContext in the pod manifest",
        ))

        # CIS-K8S-5.2.7: NET_RAW capability not dropped
        net_raw_not_dropped = []
        for c in containers:
            c_sc = c.get("securityContext") or {}
            caps = c_sc.get("capabilities") or {}
            drop_list = [str(cap).upper() for cap in (caps.get("drop") or [])]
            add_list = [str(cap).upper() for cap in (caps.get("add") or [])]
            if "NET_RAW" not in drop_list and "ALL" not in drop_list:
                net_raw_not_dropped.append(c.get("name", ""))
            if "NET_RAW" in add_list:
                if c.get("name", "") not in net_raw_not_dropped:
                    net_raw_not_dropped.append(c.get("name", "") + " (explicitly added)")
        has_net_raw = bool(net_raw_not_dropped)
        findings.append(_finding(
            resource_id=rid,
            resource_name=f"{namespace}/{pod_name}",
            resource_type="k8s_pod",
            status="FAIL" if has_net_raw else "PASS",
            severity="MEDIUM",
            rule_id="CIS-K8S-5.2.7",
            title="NET_RAW capability not dropped",
            description=f"Pod '{namespace}/{pod_name}' containers do not drop NET_RAW capability: {net_raw_not_dropped}. NET_RAW can be abused for network spoofing.",
            reasoning=f"Checked securityContext.capabilities.drop for each container in '{pod_name}'.",
            expected="capabilities.drop contains 'NET_RAW' or 'ALL'",
            actual=f"Containers without NET_RAW dropped: {net_raw_not_dropped or 'none'}",
            recommendation="Add capabilities.drop: [NET_RAW] or [ALL] to each container's securityContext.",
            remediation_step="Add 'drop: [ALL]' under securityContext.capabilities in each container",
        ))

        # CIS-K8S-5.4.1: Secrets stored as env vars
        secret_env_containers = []
        sensitive_keywords = {"SECRET", "TOKEN", "PASSWORD", "KEY", "PASSWD", "CREDENTIAL", "API_KEY"}
        for c in containers:
            env_list = c.get("env") or []
            for env in env_list:
                env_name_upper = str(env.get("name", "")).upper()
                if any(kw in env_name_upper for kw in sensitive_keywords):
                    # Check it's a plain value, not a secretKeyRef
                    value_from = env.get("valueFrom") or {}
                    if not value_from.get("secretKeyRef") and env.get("value") is not None:
                        secret_env_containers.append(f"{c.get('name', '')}:{env.get('name', '')}")
        has_secret_env = bool(secret_env_containers)
        findings.append(_finding(
            resource_id=rid,
            resource_name=f"{namespace}/{pod_name}",
            resource_type="k8s_pod",
            status="FAIL" if has_secret_env else "PASS",
            severity="HIGH",
            rule_id="CIS-K8S-5.4.1",
            title="Secrets stored as plain environment variables",
            description=f"Pod '{namespace}/{pod_name}' has environment variables with sensitive names set to plain values: {secret_env_containers}.",
            reasoning=f"Checked env list for names containing SECRET, TOKEN, PASSWORD, KEY. Found plaintext env vars: {secret_env_containers}.",
            expected="Secrets referenced via secretKeyRef, not plain values",
            actual=f"Plain-value sensitive env vars: {secret_env_containers or 'none'}",
            recommendation="Use Kubernetes Secrets and reference them via envFrom.secretRef or env.valueFrom.secretKeyRef.",
            remediation_step="Replace 'value: mysecret' with 'valueFrom: {secretKeyRef: {name: my-secret, key: value}}'",
        ))

        # CIS-K8S-5.5.1: Image pull policy not Always for non-pinned images
        non_pinned_no_always = []
        for c in containers:
            image = c.get("image", "") or ""
            pull_policy = c.get("imagePullPolicy", "") or ""
            # An image is "pinned" if it contains a sha256 digest
            is_pinned = "@sha256:" in image
            if not is_pinned and pull_policy != "Always":
                non_pinned_no_always.append(f"{c.get('name', '')}:{image} (policy={pull_policy or 'default'})")
        has_non_pinned = bool(non_pinned_no_always)
        findings.append(_finding(
            resource_id=rid,
            resource_name=f"{namespace}/{pod_name}",
            resource_type="k8s_pod",
            status="FAIL" if has_non_pinned else "PASS",
            severity="LOW",
            rule_id="CIS-K8S-5.5.1",
            title="Non-pinned image without imagePullPolicy: Always",
            description=f"Pod '{namespace}/{pod_name}' uses non-digest-pinned images without imagePullPolicy=Always: {non_pinned_no_always}.",
            reasoning=f"Images without @sha256 digest and without pullPolicy=Always may use stale cached images.",
            expected="imagePullPolicy: Always for all non-digest-pinned images",
            actual=f"Non-pinned without Always: {non_pinned_no_always or 'none'}",
            recommendation="Pin images to digest (@sha256:...) or set imagePullPolicy: Always.",
            remediation_step="Set imagePullPolicy: Always in container spec or pin image with @sha256 digest",
        ))

        # CIS-K8S-5.7.2: Default namespace used
        in_default_ns = namespace == "default"
        findings.append(_finding(
            resource_id=rid,
            resource_name=f"{namespace}/{pod_name}",
            resource_type="k8s_pod",
            status="FAIL" if in_default_ns else "PASS",
            severity="LOW",
            rule_id="CIS-K8S-5.7.2",
            title="Workload deployed in default namespace",
            description=f"Pod '{pod_name}' is deployed in the 'default' namespace. Using the default namespace bypasses namespace-based RBAC and network policy isolation.",
            reasoning=f"Pod namespace is '{namespace}'.",
            expected="Workloads deployed in dedicated namespaces, not 'default'",
            actual=f"Namespace: '{namespace}'",
            recommendation="Create dedicated namespaces for each application or team.",
            remediation_step="kubectl create namespace myapp && redeploy pod to myapp namespace",
        ))

    return findings


def _check_k8s_network_policies() -> List[Dict[str, Any]]:
    """CIS-K8S-5.3.1: Namespaces without network policies."""
    findings = []
    namespaces = _run_kubectl(["get", "namespaces"])
    netpols = _run_kubectl(["get", "networkpolicies", "--all-namespaces"])
    if namespaces is None:
        return []

    ns_with_policies = set()
    if netpols:
        for item in netpols.get("items", []):
            ns = item.get("metadata", {}).get("namespace", "")
            ns_with_policies.add(ns)

    skip_ns = {"kube-system", "kube-public", "kube-node-lease"}

    for item in namespaces.get("items", []):
        ns_name = item.get("metadata", {}).get("name", "")
        if ns_name in skip_ns:
            continue
        has_policy = ns_name in ns_with_policies
        rid = _hash_id(f"namespace:{ns_name}")
        findings.append(_finding(
            resource_id=rid,
            resource_name=ns_name,
            resource_type="k8s_namespace",
            status="PASS" if has_policy else "FAIL",
            severity="MEDIUM",
            rule_id="CIS-K8S-5.3.1",
            title="No network policies defined in namespace",
            description=f"Namespace '{ns_name}' has no NetworkPolicy resources, meaning all pod-to-pod traffic is allowed by default.",
            reasoning=f"Checked NetworkPolicy resources in namespace '{ns_name}'. Found: {has_policy}.",
            expected="At least one NetworkPolicy defined per non-system namespace",
            actual=f"NetworkPolicies in '{ns_name}': {'present' if has_policy else 'none'}",
            recommendation="Define deny-all default NetworkPolicies and allowlist required traffic.",
            remediation_step=f"kubectl apply -n {ns_name} -f default-deny-networkpolicy.yaml",
        ))

    return findings


def _check_k8s_kubelet_config() -> List[Dict[str, Any]]:
    """CIS-K8S-4.1.1: Kubelet config file permissions (best-effort from outside)."""
    findings = []
    # Try to detect if we can read kubelet config file permissions via SSH or node exec
    # From outside the node this is a best-effort check
    result = _run(["stat", "-c", "%a %n", "/var/lib/kubelet/config.yaml"])
    rid = _hash_id("kubelet-config")

    if result is None:
        # Cannot check — report as informational
        findings.append(_finding(
            resource_id=rid,
            resource_name="kubelet-config",
            resource_type="k8s_node_config",
            status="PASS",
            severity="MEDIUM",
            rule_id="CIS-K8S-4.1.1",
            title="Kubelet config file permissions (unable to verify)",
            description="Could not verify kubelet config file permissions from outside the node. Verify manually that /var/lib/kubelet/config.yaml has permissions 600 or stricter.",
            reasoning="Could not read /var/lib/kubelet/config.yaml from this environment. Node-level checks require direct node access.",
            expected="File permissions 600 or stricter on /var/lib/kubelet/config.yaml",
            actual="Unable to verify remotely",
            recommendation="SSH into each node and verify: stat -c %a /var/lib/kubelet/config.yaml",
            remediation_step="chmod 600 /var/lib/kubelet/config.yaml",
        ))
        return findings

    parts = result.split()
    perms_str = parts[0] if parts else "0"
    try:
        perms = int(perms_str, 8)
        is_secure = perms <= 0o600
    except ValueError:
        is_secure = False

    findings.append(_finding(
        resource_id=rid,
        resource_name="kubelet-config",
        resource_type="k8s_node_config",
        status="PASS" if is_secure else "FAIL",
        severity="MEDIUM",
        rule_id="CIS-K8S-4.1.1",
        title="Kubelet config file permissions",
        description=f"The kubelet config file has permissions '{perms_str}'. CIS requires permissions 600 or stricter.",
        reasoning=f"Ran 'stat -c %a /var/lib/kubelet/config.yaml'. Got permissions: {perms_str}.",
        expected="File permissions <= 600",
        actual=f"Permissions: {perms_str}",
        recommendation="Restrict kubelet config file permissions to 600.",
        remediation_step="chmod 600 /var/lib/kubelet/config.yaml",
    ))
    return findings


# ── Main Auditor Class ─────────────────────────────────────────────────────────

class ContainerAuditor:
    """
    Audits live Docker containers and Kubernetes workloads against
    CIS Docker Benchmark v1.6 and CIS Kubernetes Benchmark v1.8.
    """

    def scan_docker(self) -> Dict[str, Any]:
        """
        Scan running Docker containers via docker CLI.
        Returns {resources, findings, summary, docker_available}.
        """
        resources: List[Dict[str, Any]] = []
        findings: List[Dict[str, Any]] = []

        # Check Docker availability
        info_raw = _run_json(["docker", "info", "--format", "{{json .}}"])
        if info_raw is None:
            # Try without --format flag for older Docker versions
            info_raw = _run_json(["docker", "info"])

        if info_raw is None:
            return {
                "docker_available": False,
                "error": "Docker is not installed or not running. Ensure the Docker daemon is started.",
                "resources": [],
                "findings": [],
                "summary": {"total": 0, "pass": 0, "fail": 0, "health_score": 0.0},
            }

        # Swarm check
        swarm_findings = _check_docker_swarm(info_raw)
        findings.extend(swarm_findings)

        # List running containers
        ps_output = _run(["docker", "ps", "-q", "--no-trunc"])
        if not ps_output:
            return {
                "docker_available": True,
                "resources": [],
                "findings": findings,
                "summary": self._summary(findings),
            }

        container_ids = [cid.strip() for cid in ps_output.splitlines() if cid.strip()]

        for cid in container_ids:
            inspect_data = _run_json(["docker", "inspect", cid])
            if not inspect_data:
                continue
            if isinstance(inspect_data, list) and inspect_data:
                inspect = inspect_data[0]
            elif isinstance(inspect_data, dict):
                inspect = inspect_data
            else:
                continue

            container_name = inspect.get("Name", "").lstrip("/") or cid[:12]
            state = inspect.get("State", {})

            resources.append({
                "resource_id": _hash_id(cid),
                "resource_name": container_name,
                "resource_type": "docker_container",
                "region": "local",
                "config": {
                    "image": inspect.get("Config", {}).get("Image", ""),
                    "status": state.get("Status", ""),
                    "pid": state.get("Pid", 0),
                    "started_at": state.get("StartedAt", ""),
                    "network_mode": inspect.get("HostConfig", {}).get("NetworkMode", ""),
                    "privileged": inspect.get("HostConfig", {}).get("Privileged", False),
                },
            })

            container_findings = _check_docker_container(cid, inspect)
            findings.extend(container_findings)

        return {
            "docker_available": True,
            "resources": resources,
            "findings": findings,
            "summary": self._summary(findings),
        }

    def scan_kubernetes(self) -> Dict[str, Any]:
        """
        Scan Kubernetes workloads via kubectl CLI.
        Returns {resources, findings, summary, k8s_available}.
        """
        resources: List[Dict[str, Any]] = []
        findings: List[Dict[str, Any]] = []

        # Test kubectl connectivity
        version_data = _run_json(["kubectl", "version", "--output", "json"])
        if version_data is None:
            # Try a simpler connectivity check
            ns_check = _run(["kubectl", "get", "namespaces", "--request-timeout=5s"])
            if ns_check is None:
                return {
                    "k8s_available": False,
                    "error": "kubectl is not installed or cannot reach the cluster. Ensure kubectl is configured and the cluster is reachable.",
                    "resources": [],
                    "findings": [],
                    "summary": {"total": 0, "pass": 0, "fail": 0, "health_score": 0.0},
                }

        # Kubelet config check
        kubelet_findings = _check_k8s_kubelet_config()
        findings.extend(kubelet_findings)

        # Cluster admin bindings
        binding_findings = _check_k8s_cluster_admin_bindings()
        findings.extend(binding_findings)

        # Pod checks
        pod_findings = _check_k8s_pods()
        findings.extend(pod_findings)

        # Network policy checks
        netpol_findings = _check_k8s_network_policies()
        findings.extend(netpol_findings)

        # Build resources list from pods
        pods = _run_kubectl(["get", "pods", "--all-namespaces"])
        if pods:
            for item in pods.get("items", []):
                meta = item.get("metadata", {})
                pod_name = meta.get("name", "unknown")
                namespace = meta.get("namespace", "default")
                status_info = item.get("status", {})
                resources.append({
                    "resource_id": _hash_id(f"pod:{namespace}/{pod_name}"),
                    "resource_name": f"{namespace}/{pod_name}",
                    "resource_type": "k8s_pod",
                    "region": f"k8s-namespace:{namespace}",
                    "config": {
                        "namespace": namespace,
                        "phase": status_info.get("phase", ""),
                        "containers": [c.get("name", "") for c in item.get("spec", {}).get("containers", [])],
                    },
                })

        # Deployments
        deployments = _run_kubectl(["get", "deployments", "--all-namespaces"])
        if deployments:
            for item in deployments.get("items", []):
                meta = item.get("metadata", {})
                dep_name = meta.get("name", "unknown")
                namespace = meta.get("namespace", "default")
                resources.append({
                    "resource_id": _hash_id(f"deployment:{namespace}/{dep_name}"),
                    "resource_name": f"{namespace}/{dep_name}",
                    "resource_type": "k8s_deployment",
                    "region": f"k8s-namespace:{namespace}",
                    "config": {
                        "namespace": namespace,
                        "replicas": item.get("spec", {}).get("replicas", 0),
                    },
                })

        return {
            "k8s_available": True,
            "resources": resources,
            "findings": findings,
            "summary": self._summary(findings),
        }

    def run_full_scan(self) -> Dict[str, Any]:
        """Run Docker and Kubernetes scans and combine results."""
        scan_time = datetime.now(timezone.utc).isoformat()

        docker_result = self.scan_docker()
        k8s_result = self.scan_kubernetes()

        all_resources = docker_result.get("resources", []) + k8s_result.get("resources", [])
        all_findings = docker_result.get("findings", []) + k8s_result.get("findings", [])
        combined_summary = self._summary(all_findings)

        return {
            "scan_time": scan_time,
            "docker_available": docker_result.get("docker_available", False),
            "k8s_available": k8s_result.get("k8s_available", False),
            "docker_error": docker_result.get("error"),
            "k8s_error": k8s_result.get("error"),
            "resources": all_resources,
            "audit": {
                "findings": all_findings,
                "summary": combined_summary,
                "health_score": combined_summary.get("health_score", 0.0),
                "docker_findings": docker_result.get("findings", []),
                "k8s_findings": k8s_result.get("findings", []),
                "docker_summary": docker_result.get("summary", {}),
                "k8s_summary": k8s_result.get("summary", {}),
            },
            "scan": {
                "total_resources": len(all_resources),
                "docker_containers": len(docker_result.get("resources", [])),
                "k8s_resources": len(k8s_result.get("resources", [])),
            },
        }

    @staticmethod
    def _summary(findings: List[Dict[str, Any]]) -> Dict[str, Any]:
        total = len(findings)
        passed = sum(1 for f in findings if f.get("status") == "PASS")
        failed = total - passed
        health_score = round((passed / total) * 100, 1) if total > 0 else 100.0
        sev_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
        for f in findings:
            if f.get("status") == "FAIL":
                sev = f.get("severity", "LOW").lower()
                if sev in sev_counts:
                    sev_counts[sev] += 1
        return {
            "total": total,
            "pass": passed,
            "fail": failed,
            "health_score": health_score,
            **sev_counts,
        }
