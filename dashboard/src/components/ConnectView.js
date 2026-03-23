"use client";
import { useState, useRef, useEffect } from "react";
import { Icon } from "./Icons";

const API = "http://localhost:8000";

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

  const providers = [
    { id: "aws", name: "AWS", description: "Amazon Web Services", logo: "/logos/aws.svg", icon: "aws", connectable: true },
    { id: "azure", name: "Azure", description: "Microsoft Azure", logo: "/logos/azure.svg", icon: "azure", connectable: false },
    { id: "gcp", name: "GCP", description: "Google Cloud Platform", logo: "/logos/gcp.svg", icon: "gcp", connectable: false },
  ];

  useEffect(() => {
    fetchConnectedRepo();
    checkAwsStatus();
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
      const res = await fetch(`${API}/api/aws/configure`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ access_key: accessKey, secret_key: secretKey, region: awsRegion }),
      });
      const data = await res.json();
      if (data.status === "connected") {
        setAwsStatus({ connected: true, ...data });
        setShowAwsConfig(false);
        setAccessKey("");
        setSecretKey("");
      } else {
        setAwsError(data.message || "Invalid credentials");
      }
    } catch {
      setAwsError("Failed to connect");
    } finally {
      setAwsConfiguring(false);
    }
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
                className={`provider-card ${selectedProvider === p.id ? "active" : ""} ${isAwsConnected ? "active" : ""}`}
                onClick={() => {
                  setSelectedProvider(p.id);
                  if (isAws && !awsStatus?.connected) setShowAwsConfig(true);
                }}
                style={{ position: "relative" }}
              >
                {isAwsConnected && (
                  <div style={{ position: "absolute", top: 10, right: 10, width: 24, height: 24, borderRadius: "50%", background: "rgba(34,197,94,0.15)", display: "flex", alignItems: "center", justifyContent: "center" }}>
                    <Icon name="circle-check" size={14} />
                  </div>
                )}
                <div className="provider-logo">
                  <img src={p.logo} alt={p.name} className="provider-logo-img" style={{ width: 44, transition: "all 0.3s ease" }} />
                </div>
                <h4>{p.name}</h4>
                <p>{p.description}</p>
                {isAws && (
                  <span style={{ fontSize: 11, marginTop: 4, color: isAwsConnected ? "#22c55e" : "var(--accent-primary)", fontWeight: 600 }}>
                    {isAwsConnected ? `Connected (${awsStatus.region || "us-east-1"})` : "Click to connect"}
                  </span>
                )}
                {!isAws && (
                  <span style={{ fontSize: 11, marginTop: 4, color: "var(--text-muted)" }}>Coming soon</span>
                )}
              </div>
            );
          })}
        </div>
      </section>

      {/* ── Section 2: File Upload ──────────────────────────────────── */}
      <section style={{ marginBottom: 36 }}>
        <h3 style={{ fontSize: 18, marginBottom: 16 }}>2. Upload Terraform Files</h3>
        <div className="glass-card upload-zone" onClick={handleUploadClick}>
          <div className="upload-icon"><Icon name="upload" size={32} /></div>
          <h3>Drop your .tf files here</h3>
          <p>Or click to browse your local machine. Supports .tf and .tfvars files.</p>
          <button className="save-btn" style={{ padding: "10px 24px" }}>Select Files</button>
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
        <div style={{ position: "fixed", top: 0, left: 0, right: 0, bottom: 0, background: "rgba(0,0,0,0.6)", display: "flex", alignItems: "center", justifyContent: "center", zIndex: 1000, backdropFilter: "blur(4px)" }}
          onClick={() => { setShowAwsConfig(false); setAwsError(""); }}>
          <div className="glass-card animate-fade-in" style={{ width: 500, padding: 32, cursor: "default" }} onClick={(e) => e.stopPropagation()}>
            <div style={{ display: "flex", alignItems: "center", gap: 12, marginBottom: 24 }}>
              <div style={{ width: 48, height: 48, borderRadius: 12, background: "linear-gradient(135deg, #ff9900, #ff6600)", display: "flex", alignItems: "center", justifyContent: "center" }}>
                <Icon name="aws" size={28} />
              </div>
              <div>
                <h3 style={{ margin: 0, fontSize: 18 }}>Connect AWS Account</h3>
                <p style={{ margin: 0, fontSize: 13, color: "var(--text-secondary)" }}>Enter your programmatic access keys</p>
              </div>
            </div>

            <div style={{ marginBottom: 16 }}>
              <label style={{ display: "block", fontSize: 13, fontWeight: 500, marginBottom: 6, color: "var(--text-secondary)" }}>Access Key ID</label>
              <input type="text" value={accessKey} onChange={(e) => { setAccessKey(e.target.value); setAwsError(""); }}
                placeholder="AKIAIOSFODNN7EXAMPLE"
                style={{ width: "100%", padding: "10px 14px", borderRadius: 8, border: "1px solid var(--border-color)", background: "var(--bg-secondary)", color: "var(--text-primary)", fontSize: 14, outline: "none", boxSizing: "border-box", fontFamily: "monospace" }} />
            </div>
            <div style={{ marginBottom: 16 }}>
              <label style={{ display: "block", fontSize: 13, fontWeight: 500, marginBottom: 6, color: "var(--text-secondary)" }}>Secret Access Key</label>
              <input type="password" value={secretKey} onChange={(e) => { setSecretKey(e.target.value); setAwsError(""); }}
                placeholder="wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
                style={{ width: "100%", padding: "10px 14px", borderRadius: 8, border: "1px solid var(--border-color)", background: "var(--bg-secondary)", color: "var(--text-primary)", fontSize: 14, outline: "none", boxSizing: "border-box", fontFamily: "monospace" }} />
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
                {awsConfiguring ? "Connecting..." : (<><Icon name="aws" size={16} />Connect</>)}
              </button>
            </div>
            <p style={{ fontSize: 11, color: "var(--text-secondary)", marginTop: 12, textAlign: "center" }}>
              Credentials are stored in memory only for this session. Never persisted to disk.
            </p>
          </div>
        </div>
      )}

      {/* ── GitHub Connect Modal ── */}
      {showGitHubModal && (
        <div style={{ position: "fixed", top: 0, left: 0, right: 0, bottom: 0, background: "rgba(0,0,0,0.6)", display: "flex", alignItems: "center", justifyContent: "center", zIndex: 1000, backdropFilter: "blur(4px)" }}
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
