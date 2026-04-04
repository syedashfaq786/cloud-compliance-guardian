"use client";
import { useState, useRef, useEffect } from "react";
import { Icon } from "./Icons";

const API = "http://127.0.0.1:8000";

export default function ConnectView() {
  const [selectedProvider, setSelectedProvider] = useState(null);
  const [isScanning, setIsScanning] = useState(false);
  const [progress, setProgress] = useState(0);
  const [statusMessage, setStatusMessage] = useState("Initializing...");
  const [scanComplete, setScanComplete] = useState(false);
  const fileInputRef = useRef(null);

  // GitHub state
  const [showGitHubModal, setShowGitHubModal] = useState(false);
  const [repoUrl, setRepoUrl] = useState("");
  const [connecting, setConnecting] = useState(false);
  const [connectedRepo, setConnectedRepo] = useState(null);
  const [syncing, setSyncing] = useState(false);
  const [githubError, setGithubError] = useState("");
  const [syncResult, setSyncResult] = useState(null);

  // AWS state
  const [awsStatus, setAwsStatus] = useState(null);
  const [showAwsConfig, setShowAwsConfig] = useState(false);
  const [accessKey, setAccessKey] = useState("");
  const [secretKey, setSecretKey] = useState("");
  const [awsRegion, setAwsRegion] = useState("us-east-1");
  const [awsConfiguring, setAwsConfiguring] = useState(false);
  const [awsError, setAwsError] = useState("");
  const [showSecret, setShowSecret] = useState(false);

  // Azure state
  const [azureStatus, setAzureStatus] = useState(null);
  const [showAzureConfig, setShowAzureConfig] = useState(false);
  const [azureTenantId, setAzureTenantId] = useState("");
  const [azureClientId, setAzureClientId] = useState("");
  const [azureClientSecret, setAzureClientSecret] = useState("");
  const [azureSubscriptionId, setAzureSubscriptionId] = useState("");
  const [azureConfiguring, setAzureConfiguring] = useState(false);
  const [azureError, setAzureError] = useState("");

  // GCP state
  const [gcpStatus, setGcpStatus] = useState(null);
  const [showGcpConfig, setShowGcpConfig] = useState(false);
  const [gcpProjectId, setGcpProjectId] = useState("");
  const [gcpServiceAccountJson, setGcpServiceAccountJson] = useState("");
  const [gcpConfiguring, setGcpConfiguring] = useState(false);
  const [gcpError, setGcpError] = useState("");

  const providers = [
    { id: "aws", name: "AWS", description: "Amazon Web Services", logo: "/logos/aws.svg", icon: "aws", connectable: true },
    { id: "azure", name: "Azure", description: "Microsoft Azure", logo: "/logos/azure.svg", icon: "azure", connectable: true },
    { id: "gcp", name: "GCP", description: "Google Cloud Platform", logo: "/logos/gcp.svg", icon: "gcp", connectable: true },
  ];

  useEffect(() => {
    fetchConnectedRepo();
    checkAwsStatus();
    checkAzureStatus();
    checkGcpStatus();
  }, []);

  // ── AWS Functions ──────────────────────────────────────────────────────

  const checkAwsStatus = async () => {
    try {
      const res = await fetch(`${API}/api/aws/status`);
      const data = await res.json();
      setAwsStatus(data);
    } catch {
      setAwsStatus({ connected: false });
    }
  };

  const handleAwsConfigure = async () => {
    if (!accessKey.trim() || !secretKey.trim()) {
      setAwsError("Both Access Key ID and Secret Access Key are required");
      return;
    }
    setAwsConfiguring(true);
    setAwsError("");
    try {
      const controller = new AbortController();
      const timeoutId = setTimeout(() => controller.abort(), 30000); // 30 second timeout
      
      const res = await fetch(`${API}/api/aws/configure`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ access_key: accessKey.trim(), secret_key: secretKey.trim(), region: awsRegion }),
        signal: controller.signal
      });
      clearTimeout(timeoutId);
      
      const data = await res.json();
      if (data.status === "connected") {
        setAwsStatus({ connected: true, ...data });
        setShowAwsConfig(false);
        setAccessKey("");
        setSecretKey("");
        // Notify user about auto-discovery
        setAwsError("✓ Connected! Starting background discovery...");
        setTimeout(() => setAwsError(""), 4000); 
      } else {
        setAwsError(data.message || "Invalid credentials");
      }
    } catch (err) {
      if (err.name === "AbortError") {
        setAwsError("Connection timeout (30s) - please check your credentials and try again");
      } else {
        setAwsError("Failed to connect - check your credentials and try again");
      }
    } finally {
      setAwsConfiguring(false);
    }
  };

  const handleAwsDisconnect = async () => {
    try {
      await fetch(`${API}/api/aws/disconnect`, { method: "POST" });
      setAwsStatus({ connected: false });
    } catch {}
  };

  // ── Azure Functions ───────────────────────────────────────────────────

  const checkAzureStatus = async () => {
    try {
      const res = await fetch(`${API}/api/azure/status`);
      const data = await res.json();
      setAzureStatus(data);
    } catch { setAzureStatus({ connected: false }); }
  };

  const handleAzureConfigure = async () => {
    if (!azureTenantId.trim() || !azureClientId.trim() || !azureClientSecret.trim() || !azureSubscriptionId.trim()) {
      setAzureError("All Azure fields are required");
      return;
    }
    setAzureConfiguring(true);
    setAzureError("");
    try {
      const controller = new AbortController();
      const timeoutId = setTimeout(() => controller.abort(), 30000);
      
      const res = await fetch(`${API}/api/azure/configure`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          tenant_id: azureTenantId.trim(),
          client_id: azureClientId.trim(),
          client_secret: azureClientSecret.trim(),
          subscription_id: azureSubscriptionId.trim()
        }),
        signal: controller.signal
      });
      clearTimeout(timeoutId);
      
      const data = await res.json();
      if (data.status === "connected") {
        setAzureStatus({ connected: true, ...data });
        setShowAzureConfig(false);
        setAzureError("✓ Connected! Starting background discovery...");
        setTimeout(() => setAzureError(""), 4000);
      } else { setAzureError(data.message || "Failed to connect"); }
    } catch (err) {
      if (err.name === "AbortError") {
        setAzureError("Connection timeout (30s) - please check your credentials");
      } else {
        setAzureError("Failed to connect to Azure");
      }
    }
    finally { setAzureConfiguring(false); }
  }

  const handleAzureDisconnect = async () => {
    try {
      await fetch(`${API}/api/azure/disconnect`, { method: "POST" });
      setAzureStatus({ connected: false });
    } catch {}
  };

  // ── GCP Functions ─────────────────────────────────────────────────────

  const checkGcpStatus = async () => {
    try {
      const res = await fetch(`${API}/api/gcp/status`);
      const data = await res.json();
      setGcpStatus(data);
    } catch { setGcpStatus({ connected: false }); }
  };

  const handleGcpConfigure = async () => {
    if (!gcpProjectId.trim() || !gcpServiceAccountJson.trim()) {
      setGcpError("Project ID and Service Account JSON are required");
      return;
    }
    setGcpConfiguring(true);
    setGcpError("");
    try {
      const controller = new AbortController();
      const timeoutId = setTimeout(() => controller.abort(), 30000);
      
      const res = await fetch(`${API}/api/gcp/configure`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          project_id: gcpProjectId.trim(),
          service_account_json: gcpServiceAccountJson.trim()
        }),
        signal: controller.signal
      });
      clearTimeout(timeoutId);
      
      const data = await res.json();
      if (data.status === "connected") {
        setGcpStatus({ connected: true, ...data });
        setShowGcpConfig(false);
        setGcpError("✓ Connected! Starting background discovery...");
        setTimeout(() => setGcpError(""), 4000);
      } else { setGcpError(data.message || "Failed to connect"); }
    } catch (err) {
      if (err.name === "AbortError") {
        setGcpError("Connection timeout (30s) - please check your credentials");
      } else {
        setGcpError("Failed to connect to GCP");
      }
    }
    finally { setGcpConfiguring(false); }
  };

  const handleGcpDisconnect = async () => {
    try {
      await fetch(`${API}/api/gcp/disconnect`, { method: "POST" });
      setGcpStatus({ connected: false });
    } catch {}
  };

  // ── GitHub Functions ───────────────────────────────────────────────────

  const fetchConnectedRepo = async () => {
    try {
      const res = await fetch(`${API}/api/github/repo`);
      const data = await res.json();
      if (data.connected) setConnectedRepo(data);
    } catch {}
  };

  const handleConnectGitHub = async () => {
    if (!repoUrl.trim()) { setGithubError("Please enter a repository URL"); return; }
    if (!repoUrl.includes("github.com")) { setGithubError("Please enter a valid GitHub URL"); return; }
    setConnecting(true);
    setGithubError("");
    try {
      const res = await fetch(`${API}/api/github/connect`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ url: repoUrl }),
      });
      if (!res.ok) { const err = await res.json(); throw new Error(err.detail || "Failed to connect"); }
      const data = await res.json();
      setConnectedRepo({ ...data, connected: true });
      setShowGitHubModal(false);
      setRepoUrl("");
      if (data.scan_triggered) {
        setSyncResult({ message: data.message || "Repository cloned and scan started. Check the Audits tab for results." });
      }
    } catch (err) { setGithubError(err.message); }
    finally { setConnecting(false); }
  };

  const handleSyncRepo = async () => {
    setSyncing(true);
    setSyncResult(null);
    try {
      const res = await fetch(`${API}/api/github/sync`, { method: "POST" });
      if (!res.ok) { const err = await res.json(); throw new Error(err.detail || "Sync failed"); }
      const data = await res.json();
      setSyncResult({ message: data.message || "Sync started." });
      fetchConnectedRepo();
    } catch (err) { setSyncResult({ error: err.message }); }
    finally { setSyncing(false); }
  };

  const handleDisconnect = async () => {
    try {
      const res = await fetch(`${API}/api/github/disconnect`, { method: "DELETE" });
      if (res.ok) { setConnectedRepo(null); setSyncResult(null); }
    } catch {}
  };

  // ── File Upload ────────────────────────────────────────────────────────

  const handleUploadClick = () => fileInputRef.current.click();

  const handleFileChange = (e) => {
    if (e.target.files.length > 0) startScanning();
  };

  const startScanning = async () => {
    setIsScanning(true);
    setProgress(0);
    setScanComplete(false);
    const steps = [
      { p: 10, m: "Parsing HCL files..." },
      { p: 30, m: "Extracting resource definitions..." },
      { p: 50, m: "Running Cisco Sec-8B Inference..." },
      { p: 70, m: "Analyzing against CIS Benchmarks..." },
      { p: 90, m: "Calculating compliance score..." },
      { p: 100, m: "Audit complete!" },
    ];
    let currentStep = 0;
    const interval = setInterval(() => {
      setProgress((prev) => {
        if (prev >= 100) { clearInterval(interval); setScanComplete(true); return 100; }
        const next = prev + 2;
        if (currentStep < steps.length && next >= steps[currentStep].p) { setStatusMessage(steps[currentStep].m); currentStep++; }
        return next;
      });
    }, 100);
    try {
      await fetch(`${API}/api/scan`, { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ directory: "tests/fixtures" }) });
    } catch {}
  };

  // ── Scanning View ──────────────────────────────────────────────────────

  if (isScanning) {
    return (
      <div className="animate-fade-in scanning-view">
        <div className="scanning-animation">
          <div className="scanning-ring"></div>
          <div className="scanning-icon">
            <Icon name={scanComplete ? "circle-check" : (selectedProvider || "aws")} size={48} />
          </div>
        </div>
        <h2>{scanComplete ? "Scan Successful" : "Scanning Infrastructure..."}</h2>
        <p style={{ color: "var(--text-secondary)", maxWidth: 450 }}>
          {scanComplete ? "Your infrastructure has been analyzed." : "Processing your Terraform configuration using Cisco Sec-8B."}
        </p>
        <div className="progress-container">
          <div className="progress-info"><span>{statusMessage}</span><span>{Math.round(progress)}%</span></div>
          <div className="progress-bar-bg"><div className="progress-bar-fill" style={{ width: `${progress}%` }}></div></div>
        </div>
        {scanComplete && (
          <button className="save-btn animate-fade-in" style={{ marginTop: 32 }} onClick={() => window.location.reload()}>
            Return to Dashboard
          </button>
        )}
      </div>
    );
  }

  // ── Main View ──────────────────────────────────────────────────────────

  return (
    <div className="animate-fade-in">
      <div className="page-header">
        <h2>Connect Infrastructure</h2>
        <p>Connect your cloud accounts, upload Terraform files, or link a GitHub repository for compliance auditing.</p>
      </div>

      <input type="file" multiple ref={fileInputRef} style={{ display: "none" }} onChange={handleFileChange} accept=".tf,.tfvars" />

      {/* ── Section 1: Cloud Providers ──────────────────────────────── */}
      <section style={{ marginBottom: 36 }}>
        <h3 style={{ fontSize: 18, marginBottom: 16 }}>1. Connect Cloud Provider</h3>
        <div className="connect-grid">
          {providers.map((p) => {
            const isAws = p.id === "aws";
            const isAwsConnected = isAws && awsStatus?.connected;
            return (
              <div
                key={p.id}
                className={`provider-card ${selectedProvider === p.id ? "active" : ""} ${
                  (p.id === "aws" && awsStatus?.connected) ||
                  (p.id === "azure" && azureStatus?.connected) ||
                  (p.id === "gcp" && gcpStatus?.connected) ? "active" : ""
                }`}
                onClick={() => {
                  setSelectedProvider(p.id);
                  if (p.id === "aws" && !awsStatus?.connected) setShowAwsConfig(true);
                  if (p.id === "azure" && !azureStatus?.connected) setShowAzureConfig(true);
                  if (p.id === "gcp" && !gcpStatus?.connected) setShowGcpConfig(true);
                }}
                style={{ position: "relative" }}
              >
                {((p.id === "aws" && awsStatus?.connected) ||
                  (p.id === "azure" && azureStatus?.connected) ||
                  (p.id === "gcp" && gcpStatus?.connected)) && (
                  <div style={{ position: "absolute", top: 10, right: 10, width: 24, height: 24, borderRadius: "50%", background: "rgba(34,197,94,0.15)", display: "flex", alignItems: "center", justifyContent: "center" }}>
                    <Icon name="circle-check" size={14} />
                  </div>
                )}
                <div className="provider-logo">
                  <img src={p.logo} alt={p.name} className="provider-logo-img" style={{ width: 44, transition: "all 0.3s ease" }} />
                </div>
                <h4>{p.name}</h4>
                <p>{p.description}</p>
                
                {p.id === "aws" && (
                  <div style={{ display: "flex", flexDirection: "column", alignItems: "center", width: "100%" }}>
                    <span style={{ fontSize: 11, marginTop: 4, color: awsStatus?.connected ? "#22c55e" : "var(--accent-primary)", fontWeight: 600 }}>
                      {awsStatus?.connected ? `Connected (${awsStatus.region || "us-east-1"})` : "Click to connect"}
                    </span>
                    {awsStatus?.connected && (
                      <button onClick={(e) => { e.stopPropagation(); handleAwsDisconnect(); }} style={{ marginTop: 6, padding: "4px 12px", fontSize: 11, background: "rgba(220,53,69,0.1)", color: "#dc3545", border: "1px solid rgba(220,53,69,0.3)", borderRadius: 6, cursor: "pointer", fontWeight: 500 }}>Disconnect</button>
                    )}
                  </div>
                )}

                {p.id === "azure" && (
                  <div style={{ display: "flex", flexDirection: "column", alignItems: "center", width: "100%" }}>
                    <span style={{ fontSize: 11, marginTop: 4, color: azureStatus?.connected ? "#22c55e" : "var(--accent-primary)", fontWeight: 600 }}>
                      {azureStatus?.connected ? `Connected (${azureStatus.tenant_id})` : "Click to connect"}
                    </span>
                    {azureStatus?.connected && (
                      <button onClick={(e) => { e.stopPropagation(); handleAzureDisconnect(); }} style={{ marginTop: 6, padding: "4px 12px", fontSize: 11, background: "rgba(220,53,69,0.1)", color: "#dc3545", border: "1px solid rgba(220,53,69,0.3)", borderRadius: 6, cursor: "pointer", fontWeight: 500 }}>Disconnect</button>
                    )}
                  </div>
                )}

                {p.id === "gcp" && (
                  <div style={{ display: "flex", flexDirection: "column", alignItems: "center", width: "100%" }}>
                    <span style={{ fontSize: 11, marginTop: 4, color: gcpStatus?.connected ? "#22c55e" : "var(--accent-primary)", fontWeight: 600 }}>
                      {gcpStatus?.connected ? `Connected (${gcpStatus.project_id})` : "Click to connect"}
                    </span>
                    {gcpStatus?.connected && (
                      <button onClick={(e) => { e.stopPropagation(); handleGcpDisconnect(); }} style={{ marginTop: 6, padding: "4px 12px", fontSize: 11, background: "rgba(220,53,69,0.1)", color: "#dc3545", border: "1px solid rgba(220,53,69,0.3)", borderRadius: 6, cursor: "pointer", fontWeight: 500 }}>Disconnect</button>
                    )}
                  </div>
                )}
              </div>
            );
          })}
        </div>
      </section>

      {/* ── Section 2: Infrastructure as Code Upload ─────────────── */}
      <section style={{ marginBottom: 36 }}>
        <h3 style={{ fontSize: 18, marginBottom: 6 }}>2. Upload Infrastructure as Code</h3>
        <p style={{ fontSize: 13, color: "var(--text-secondary)", marginBottom: 20 }}>
          Upload configuration files from Terraform, Docker, or Kubernetes for compliance analysis.
        </p>

        {/* Three upload cards */}
        <div style={{ display: "grid", gridTemplateColumns: "repeat(3, 1fr)", gap: 16, marginBottom: 16 }}>
          {[
            {
              logo: "/logos/terraform.svg",
              name: "Terraform",
              desc: "HCL infrastructure definitions",
              ext: ".tf, .tfvars",
              accept: ".tf,.tfvars",
              bg: "#5c4ee510",
              border: "#5c4ee530",
              badge: "#5c4ee5",
            },
            {
              logo: "/logos/docker.svg",
              name: "Docker",
              desc: "Container image definitions",
              ext: "Dockerfile, .yaml",
              accept: ".yaml,.yml,Dockerfile",
              bg: "#2496ed10",
              border: "#2496ed30",
              badge: "#2496ed",
            },
            {
              logo: "/logos/kubernetes.svg",
              name: "Kubernetes",
              desc: "Cluster resource manifests",
              ext: ".yaml, .json",
              accept: ".yaml,.yml,.json",
              bg: "#326ce510",
              border: "#326ce530",
              badge: "#326ce5",
            },
          ].map((tool) => (
            <div
              key={tool.name}
              onClick={handleUploadClick}
              style={{
                display: "flex", flexDirection: "column", alignItems: "center",
                padding: "28px 20px 20px", borderRadius: 16, cursor: "pointer",
                background: tool.bg,
                border: `1.5px dashed ${tool.border}`,
                transition: "all 0.2s ease",
                position: "relative",
              }}
              onMouseEnter={e => { e.currentTarget.style.transform = "translateY(-3px)"; e.currentTarget.style.boxShadow = `0 8px 24px ${tool.border}`; }}
              onMouseLeave={e => { e.currentTarget.style.transform = "none"; e.currentTarget.style.boxShadow = "none"; }}
            >
              {/* Logo */}
              <div style={{ width: 56, height: 56, marginBottom: 14, display: "flex", alignItems: "center", justifyContent: "center" }}>
                <img src={tool.logo} alt={tool.name} style={{ width: 52, height: 52, objectFit: "contain" }} />
              </div>

              <div style={{ fontSize: 15, fontWeight: 700, color: "var(--text-primary)", marginBottom: 4 }}>{tool.name}</div>
              <div style={{ fontSize: 12, color: "var(--text-secondary)", marginBottom: 12, textAlign: "center" }}>{tool.desc}</div>

              {/* File types badge */}
              <div style={{ fontSize: 11, fontWeight: 600, color: tool.badge, background: `${tool.badge}12`, border: `1px solid ${tool.badge}25`, padding: "3px 10px", borderRadius: 20, marginBottom: 16 }}>
                {tool.ext}
              </div>

              {/* Upload button */}
              <button
                onClick={(e) => { e.stopPropagation(); handleUploadClick(); }}
                style={{
                  display: "flex", alignItems: "center", gap: 6,
                  padding: "8px 18px", borderRadius: 8,
                  background: tool.badge, color: "#fff",
                  border: "none", fontSize: 13, fontWeight: 600, cursor: "pointer",
                  width: "100%", justifyContent: "center",
                  transition: "opacity 0.15s",
                }}
                onMouseEnter={e => e.currentTarget.style.opacity = "0.85"}
                onMouseLeave={e => e.currentTarget.style.opacity = "1"}
              >
                <Icon name="upload" size={14} /> Upload Files
              </button>
            </div>
          ))}
        </div>

        {/* Drag & drop fallback zone */}
        <div className="glass-card upload-zone" onClick={handleUploadClick}
          style={{ padding: "18px 24px", display: "flex", flexDirection: "row", alignItems: "center", justifyContent: "space-between", gap: 16 }}>
          <div style={{ display: "flex", alignItems: "center", gap: 14 }}>
            <Icon name="upload" size={24} style={{ color: "var(--accent-amber)", flexShrink: 0 }} />
            <div>
              <div style={{ fontSize: 14, fontWeight: 600, color: "var(--text-primary)" }}>Or drag & drop any file here</div>
              <div style={{ fontSize: 12, color: "var(--text-secondary)" }}>Supports .tf, .tfvars, Dockerfile, .yaml, .json</div>
            </div>
          </div>
          <button className="save-btn" style={{ padding: "8px 20px", flexShrink: 0 }}>Browse Files</button>
        </div>
      </section>

      {/* ── Section 3: GitHub ──────────────────────────────────────── */}
      <section>
        <h3 style={{ fontSize: 18, marginBottom: 16 }}>3. GitHub Repository</h3>
        {connectedRepo ? (
          <div className="github-connect" style={{ flexDirection: "column", alignItems: "stretch", gap: 20 }}>
            <div style={{ display: "flex", alignItems: "center", gap: 16 }}>
              <div className="github-icon-large" style={{ background: "rgba(40, 167, 69, 0.15)" }}>
                <Icon name="circle-check" size={48} />
              </div>
              <div style={{ flex: 1 }}>
                <h3 style={{ margin: 0, fontSize: 18 }}><Icon name="github" size={18} /> {connectedRepo.name}</h3>
                <p style={{ margin: "4px 0 0", color: "var(--text-secondary)", fontSize: 13 }}>{connectedRepo.url}</p>
                {connectedRepo.last_sync && <p style={{ margin: "2px 0 0", color: "var(--text-secondary)", fontSize: 12 }}>Last synced: {new Date(connectedRepo.last_sync).toLocaleString()}</p>}
                {connectedRepo.metadata?.last_commit && (
                  <p style={{ margin: "4px 0 0", color: "var(--text-secondary)", fontSize: 12 }}>
                    Latest commit: <code style={{ fontSize: 11, background: "var(--bg-tertiary)", padding: "2px 6px", borderRadius: 4 }}>{connectedRepo.metadata.last_commit.sha}</code> — {connectedRepo.metadata.last_commit.message}
                  </p>
                )}
              </div>
            </div>
            {syncResult && (
              <div style={{ padding: "12px 16px", borderRadius: 8, background: syncResult.error ? "rgba(220,53,69,0.1)" : "rgba(40,167,69,0.1)", border: `1px solid ${syncResult.error ? "rgba(220,53,69,0.3)" : "rgba(40,167,69,0.3)"}`, fontSize: 13 }}>
                {syncResult.error ? <span style={{ color: "#dc3545" }}>Sync failed: {syncResult.error}</span> : <span style={{ color: "#28a745" }}>{syncResult.message}</span>}
              </div>
            )}
            <div style={{ display: "flex", gap: 12 }}>
              <button className="save-btn" onClick={handleSyncRepo} disabled={syncing} style={{ flex: 1, display: "flex", alignItems: "center", justifyContent: "center", gap: 8 }}>
                {syncing ? (<><span style={{ width: 16, height: 16, border: "2px solid rgba(255,255,255,0.3)", borderTopColor: "#fff", borderRadius: "50%", animation: "spin 0.8s linear infinite", display: "inline-block" }}></span>Syncing...</>) : (<><Icon name="refresh" size={16} />Sync & Scan</>)}
              </button>
              <button className="connect-btn" onClick={handleDisconnect} style={{ background: "rgba(220,53,69,0.1)", color: "#dc3545", border: "1px solid rgba(220,53,69,0.3)" }}>Disconnect</button>
            </div>
          </div>
        ) : (
          <div className="github-connect">
            <div className="github-icon-large"><Icon name="github" size={48} /></div>
            <div className="github-info">
              <h3>Connect GitHub Repository</h3>
              <p>Link your repository to enable automated compliance scanning of Terraform code on every push.</p>
            </div>
            <button className="connect-btn" onClick={() => setShowGitHubModal(true)}><Icon name="github" size={18} />Connect GitHub</button>
          </div>
        )}
      </section>

      {/* ── AWS Config Modal ── */}
      {showAwsConfig && (
        <div style={{ position: "fixed", top: 0, left: 0, right: 0, bottom: 0, background: "rgba(10, 15, 25, 0.92)", display: "flex", alignItems: "center", justifyContent: "center", zIndex: 1000, backdropFilter: "blur(8px)" }}
          onClick={() => { setShowAwsConfig(false); setAwsError(""); }}>
          <div className="glass-card animate-fade-in" style={{ width: 500, padding: 32, cursor: "default" }} onClick={(e) => e.stopPropagation()}>
            <div style={{ display: "flex", alignItems: "center", gap: 14, marginBottom: 24 }}>
              <img src="/logos/aws.svg" alt="AWS" style={{ width: 48, height: 48, objectFit: "contain" }} />
              <div>
                <h3 style={{ margin: 0, fontSize: 18 }}>Connect AWS Account</h3>
                <p style={{ margin: 0, fontSize: 13, color: "var(--text-secondary)" }}>Enter your programmatic access keys</p>
              </div>
            </div>

            <div style={{ marginBottom: 16 }}>
              <label style={{ display: "block", fontSize: 13, fontWeight: 500, marginBottom: 6, color: "var(--text-secondary)" }}>Access Key ID</label>
              <input type="text" value={accessKey} onChange={(e) => { setAccessKey(e.target.value); setAwsError(""); }}
                placeholder="AKIAIOSFODNN7EXAMPLE"
                autoComplete="off" autoCorrect="off" spellCheck="false" data-form-type="other"
                style={{ width: "100%", padding: "10px 14px", borderRadius: 8, border: "1px solid var(--border-color)", background: "var(--bg-secondary)", color: "var(--text-primary)", fontSize: 14, outline: "none", boxSizing: "border-box", fontFamily: "monospace" }} />
            </div>
            <div style={{ marginBottom: 16 }}>
              <label style={{ display: "block", fontSize: 13, fontWeight: 500, marginBottom: 6, color: "var(--text-secondary)" }}>Secret Access Key</label>
              <div style={{ position: "relative" }}>
                <input type={showSecret ? "text" : "password"} value={secretKey} onChange={(e) => { setSecretKey(e.target.value); setAwsError(""); }}
                  placeholder="wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
                  autoComplete="new-password" autoCorrect="off" spellCheck="false" data-form-type="other"
                  style={{ width: "100%", padding: "10px 14px", paddingRight: 44, borderRadius: 8, border: "1px solid var(--border-color)", background: "var(--bg-secondary)", color: "var(--text-primary)", fontSize: 14, outline: "none", boxSizing: "border-box", fontFamily: "monospace" }} />
                <button type="button" onClick={() => setShowSecret(!showSecret)}
                  style={{ position: "absolute", right: 8, top: "50%", transform: "translateY(-50%)", background: "none", border: "none", cursor: "pointer", padding: 4, color: "var(--text-muted)", fontSize: 12 }}>
                  {showSecret ? "Hide" : "Show"}
                </button>
              </div>
            </div>
            <div style={{ marginBottom: 20 }}>
              <label style={{ display: "block", fontSize: 13, fontWeight: 500, marginBottom: 6, color: "var(--text-secondary)" }}>Region</label>
              <select value={awsRegion} onChange={(e) => setAwsRegion(e.target.value)}
                style={{ width: "100%", padding: "10px 14px", borderRadius: 8, border: "1px solid var(--border-color)", background: "var(--bg-secondary)", color: "var(--text-primary)", fontSize: 14, outline: "none", boxSizing: "border-box" }}>
                <option value="us-east-1">US East (N. Virginia)</option>
                <option value="us-west-2">US West (Oregon)</option>
                <option value="eu-west-1">EU (Ireland)</option>
                <option value="ap-south-1">Asia Pacific (Mumbai)</option>
                <option value="ap-southeast-1">Asia Pacific (Singapore)</option>
              </select>
            </div>

            {awsError && <p style={{ color: "#ef4444", fontSize: 13, marginBottom: 12 }}>{awsError}</p>}

            <div style={{ display: "flex", gap: 12, justifyContent: "flex-end" }}>
              <button className="connect-btn" onClick={() => { setShowAwsConfig(false); setAwsError(""); }}
                style={{ background: "var(--bg-tertiary)", color: "var(--text-primary)", border: "1px solid var(--border-color)" }}>Cancel</button>
              <button className="save-btn" onClick={handleAwsConfigure} disabled={awsConfiguring}
                style={{ display: "flex", alignItems: "center", gap: 8 }}>
                {awsConfiguring ? "Connecting..." : "Connect"}
              </button>
            </div>
            <p style={{ fontSize: 11, color: "var(--text-secondary)", marginTop: 12, textAlign: "center" }}>
              Credentials are saved locally and persist across restarts. Click Disconnect to remove them.
            </p>
          </div>
        </div>
      )}

      {/* ── Azure Config Modal ── */}
      {showAzureConfig && (
        <div style={{ position: "fixed", top: 0, left: 0, right: 0, bottom: 0, background: "rgba(10, 15, 25, 0.92)", display: "flex", alignItems: "center", justifyContent: "center", zIndex: 1000, backdropFilter: "blur(8px)" }}
          onClick={() => { setShowAzureConfig(false); setAzureError(""); }}>
          <div className="glass-card animate-fade-in" style={{ width: 500, padding: 32, cursor: "default" }} onClick={(e) => e.stopPropagation()}>
            <div style={{ display: "flex", alignItems: "center", gap: 14, marginBottom: 24 }}>
              <img src="/logos/azure.svg" alt="Azure" style={{ width: 48, height: 48, objectFit: "contain" }} />
              <div>
                <h3 style={{ margin: 0, fontSize: 18 }}>Connect Azure Account</h3>
                <p style={{ margin: 0, fontSize: 13, color: "var(--text-secondary)" }}>Enter your service principal credentials</p>
              </div>
            </div>

            <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 16 }}>
              <div style={{ marginBottom: 16 }}>
                <label style={{ display: "block", fontSize: 13, fontWeight: 500, marginBottom: 6, color: "var(--text-secondary)" }}>Tenant ID</label>
                <input type="text" value={azureTenantId} onChange={(e) => setAzureTenantId(e.target.value)} placeholder="00000000-0000..." style={{ width: "100%", padding: "10px 14px", borderRadius: 8, border: "1px solid var(--border-color)", background: "var(--bg-secondary)", color: "var(--text-primary)", fontSize: 14, outline: "none", boxSizing: "border-box" }} />
              </div>
              <div style={{ marginBottom: 16 }}>
                <label style={{ display: "block", fontSize: 13, fontWeight: 500, marginBottom: 6, color: "var(--text-secondary)" }}>Client ID</label>
                <input type="text" value={azureClientId} onChange={(e) => setAzureClientId(e.target.value)} placeholder="00000000-0000..." style={{ width: "100%", padding: "10px 14px", borderRadius: 8, border: "1px solid var(--border-color)", background: "var(--bg-secondary)", color: "var(--text-primary)", fontSize: 14, outline: "none", boxSizing: "border-box" }} />
              </div>
            </div>
            <div style={{ marginBottom: 16 }}>
              <label style={{ display: "block", fontSize: 13, fontWeight: 500, marginBottom: 6, color: "var(--text-secondary)" }}>Client Secret</label>
              <input type="password" value={azureClientSecret} onChange={(e) => setAzureClientSecret(e.target.value)} placeholder="••••••••••••••••" style={{ width: "100%", padding: "10px 14px", borderRadius: 8, border: "1px solid var(--border-color)", background: "var(--bg-secondary)", color: "var(--text-primary)", fontSize: 14, outline: "none", boxSizing: "border-box" }} />
            </div>
            <div style={{ marginBottom: 20 }}>
              <label style={{ display: "block", fontSize: 13, fontWeight: 500, marginBottom: 6, color: "var(--text-secondary)" }}>Subscription ID</label>
              <input type="text" value={azureSubscriptionId} onChange={(e) => setAzureSubscriptionId(e.target.value)} placeholder="00000000-0000..." style={{ width: "100%", padding: "10px 14px", borderRadius: 8, border: "1px solid var(--border-color)", background: "var(--bg-secondary)", color: "var(--text-primary)", fontSize: 14, outline: "none", boxSizing: "border-box" }} />
            </div>

            {azureError && <p style={{ color: "#ef4444", fontSize: 13, marginBottom: 12 }}>{azureError}</p>}

            <div style={{ display: "flex", gap: 12, justifyContent: "flex-end" }}>
              <button className="connect-btn" onClick={() => setShowAzureConfig(false)} style={{ background: "var(--bg-tertiary)", color: "var(--text-primary)", border: "1px solid var(--border-color)" }}>Cancel</button>
              <button className="save-btn" onClick={handleAzureConfigure} disabled={azureConfiguring}>{azureConfiguring ? "Connecting..." : "Connect Azure"}</button>
            </div>
          </div>
        </div>
      )}

      {/* ── GCP Config Modal ── */}
      {showGcpConfig && (
        <div style={{ position: "fixed", top: 0, left: 0, right: 0, bottom: 0, background: "rgba(10, 15, 25, 0.92)", display: "flex", alignItems: "center", justifyContent: "center", zIndex: 1000, backdropFilter: "blur(8px)" }}
          onClick={() => { setShowGcpConfig(false); setGcpError(""); }}>
          <div className="glass-card animate-fade-in" style={{ width: 500, padding: 32, cursor: "default" }} onClick={(e) => e.stopPropagation()}>
            <div style={{ display: "flex", alignItems: "center", gap: 14, marginBottom: 24 }}>
              <img src="/logos/gcp.svg" alt="GCP" style={{ width: 48, height: 48, objectFit: "contain" }} />
              <div>
                <h3 style={{ margin: 0, fontSize: 18 }}>Connect GCP Project</h3>
                <p style={{ margin: 0, fontSize: 13, color: "var(--text-secondary)" }}>Enter your project details and service account</p>
              </div>
            </div>

            <div style={{ marginBottom: 16 }}>
              <label style={{ display: "block", fontSize: 13, fontWeight: 500, marginBottom: 6, color: "var(--text-secondary)" }}>Project ID</label>
              <input type="text" value={gcpProjectId} onChange={(e) => setGcpProjectId(e.target.value)} placeholder="my-awesome-project-123" style={{ width: "100%", padding: "10px 14px", borderRadius: 8, border: "1px solid var(--border-color)", background: "var(--bg-secondary)", color: "var(--text-primary)", fontSize: 14, outline: "none", boxSizing: "border-box" }} />
            </div>
            <div style={{ marginBottom: 20 }}>
              <label style={{ display: "block", fontSize: 13, fontWeight: 500, marginBottom: 6, color: "var(--text-secondary)" }}>Service Account Key (JSON)</label>
              <textarea value={gcpServiceAccountJson} onChange={(e) => setGcpServiceAccountJson(e.target.value)} placeholder='{ "type": "service_account", ... }' style={{ width: "100%", height: 120, padding: "10px 14px", borderRadius: 8, border: "1px solid var(--border-color)", background: "var(--bg-secondary)", color: "var(--text-primary)", fontSize: 12, outline: "none", boxSizing: "border-box", fontFamily: "monospace", resize: "none" }} />
            </div>

            {gcpError && <p style={{ color: "#ef4444", fontSize: 13, marginBottom: 12 }}>{gcpError}</p>}

            <div style={{ display: "flex", gap: 12, justifyContent: "flex-end" }}>
              <button className="connect-btn" onClick={() => setShowGcpConfig(false)} style={{ background: "var(--bg-tertiary)", color: "var(--text-primary)", border: "1px solid var(--border-color)" }}>Cancel</button>
              <button className="save-btn" onClick={handleGcpConfigure} disabled={gcpConfiguring}>{gcpConfiguring ? "Connecting..." : "Connect GCP"}</button>
            </div>
          </div>
        </div>
      )}

      {/* ── GitHub Connect Modal ── */}
      {showGitHubModal && (
        <div style={{ position: "fixed", top: 0, left: 0, right: 0, bottom: 0, background: "rgba(10, 15, 25, 0.92)", display: "flex", alignItems: "center", justifyContent: "center", zIndex: 1000, backdropFilter: "blur(8px)" }}
          onClick={() => { setShowGitHubModal(false); setGithubError(""); }}>
          <div className="glass-card animate-fade-in" style={{ width: 480, padding: 32, cursor: "default" }} onClick={(e) => e.stopPropagation()}>
            <div style={{ display: "flex", alignItems: "center", gap: 12, marginBottom: 24 }}>
              <div style={{ width: 48, height: 48, borderRadius: 12, background: "var(--bg-tertiary)", display: "flex", alignItems: "center", justifyContent: "center" }}>
                <Icon name="github" size={28} />
              </div>
              <div>
                <h3 style={{ margin: 0, fontSize: 18 }}>Connect GitHub Repository</h3>
                <p style={{ margin: 0, fontSize: 13, color: "var(--text-secondary)" }}>Enter the URL of your Terraform repository</p>
              </div>
            </div>
            <div style={{ marginBottom: 20 }}>
              <label style={{ display: "block", fontSize: 13, fontWeight: 500, marginBottom: 6, color: "var(--text-secondary)" }}>Repository URL</label>
              <input type="text" value={repoUrl} onChange={(e) => { setRepoUrl(e.target.value); setGithubError(""); }}
                placeholder="https://github.com/username/repo"
                style={{ width: "100%", padding: "10px 14px", borderRadius: 8, border: `1px solid ${githubError ? "#dc3545" : "var(--border-color)"}`, background: "var(--bg-secondary)", color: "var(--text-primary)", fontSize: 14, outline: "none", boxSizing: "border-box" }}
                onKeyDown={(e) => e.key === "Enter" && handleConnectGitHub()} autoFocus />
              {githubError && <p style={{ color: "#dc3545", fontSize: 12, marginTop: 6 }}>{githubError}</p>}
            </div>
            <div style={{ display: "flex", gap: 12, justifyContent: "flex-end" }}>
              <button className="connect-btn" onClick={() => { setShowGitHubModal(false); setGithubError(""); }}
                style={{ background: "var(--bg-tertiary)", color: "var(--text-primary)", border: "1px solid var(--border-color)" }}>Cancel</button>
              <button className="save-btn" onClick={handleConnectGitHub} disabled={connecting}
                style={{ display: "flex", alignItems: "center", gap: 8 }}>
                {connecting ? (<><span style={{ width: 14, height: 14, border: "2px solid rgba(255,255,255,0.3)", borderTopColor: "#fff", borderRadius: "50%", animation: "spin 0.8s linear infinite", display: "inline-block" }}></span>Cloning...</>) : (<><Icon name="github" size={16} />Connect</>)}
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
