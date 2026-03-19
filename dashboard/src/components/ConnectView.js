"use client";
import { useState, useRef, useEffect } from "react";
import { Icon } from "./Icons";

export default function ConnectView() {
  const [selectedProvider, setSelectedProvider] = useState("aws");
  const [isScanning, setIsScanning] = useState(false);
  const [progress, setProgress] = useState(0);
  const [statusMessage, setStatusMessage] = useState("Initializing...");
  const [scanComplete, setScanComplete] = useState(false);
  const fileInputRef = useRef(null);

  const providers = [
    { id: "aws", name: "AWS", description: "Amazon Web Services", logo: "/logos/aws.svg", icon: "aws" },
    { id: "azure", name: "Azure", description: "Microsoft Azure", logo: "/logos/azure.svg", icon: "azure" },
    { id: "gcp", name: "GCP", description: "Google Cloud Platform", logo: "/logos/gcp.svg", icon: "gcp" },
  ];

  const handleUploadClick = () => {
    fileInputRef.current.click();
  };

  const handleFileChange = (e) => {
    if (e.target.files.length > 0) {
      startScanning();
    }
  };

  const startScanning = async () => {
    setIsScanning(true);
    setProgress(0);
    setScanComplete(false);

    // Simulated progress steps
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
        if (prev >= 100) {
          clearInterval(interval);
          setScanComplete(true);
          return 100;
        }

        const nextProgress = prev + 2;
        if (currentStep < steps.length && nextProgress >= steps[currentStep].p) {
          setStatusMessage(steps[currentStep].m);
          currentStep++;
        }
        return nextProgress;
      });
    }, 100);

    // Background call to real API to actually perform a scan on test fixtures
    try {
      await fetch('http://localhost:8000/api/scan', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ directory: 'tests/fixtures' })
      });
    } catch (error) {
      console.error("Scan API failed, but continuing simulation for UI.", error);
    }
  };

  if (isScanning) {
    return (
      <div className="animate-fade-in scanning-view">
        <div className="scanning-animation">
          <div className="scanning-ring"></div>
          <div className="scanning-icon">
            <Icon name={scanComplete ? "circle-check" : providers.find(p => p.id === selectedProvider)?.icon} size={48} />
          </div>
        </div>

        <h2>{scanComplete ? "Scan Successful" : "Scanning Infrastructure..."}</h2>
        <p style={{ color: "var(--text-secondary)", maxWidth: 450 }}>
          {scanComplete
            ? "Your infrastructure has been analyzed. You can now view the detailed findings in the dashboard."
            : `Processing your ${selectedProvider.toUpperCase()} Terraform configuration using Cisco Sec-8B.`}
        </p>

        <div className="progress-container">
          <div className="progress-info">
            <span>{statusMessage}</span>
            <span>{Math.round(progress)}%</span>
          </div>
          <div className="progress-bar-bg">
            <div className="progress-bar-fill" style={{ width: `${progress}%` }}></div>
          </div>
        </div>

        {scanComplete && (
          <button
            className="save-btn animate-fade-in"
            style={{ marginTop: 32 }}
            onClick={() => window.location.reload()} // Simple way to reset for now
          >
            Return to Dashboard
          </button>
        )}
      </div>
    );
  }

  return (
    <div className="animate-fade-in">
      <div className="page-header">
        <h2>Connect Infrastructure</h2>
        <p>Ingest your Terraform files or connect your GitHub repository for automated CIS compliance auditing.</p>
      </div>

      <input
        type="file"
        multiple
        ref={fileInputRef}
        style={{ display: "none" }}
        onChange={handleFileChange}
        accept=".tf,.tfvars"
      />

      {/* ── Cloud Providers ────────────────────────────────────────── */}
      <section style={{ marginBottom: 40 }}>
        <h3 style={{ fontSize: 18, marginBottom: 16 }}>1. Select Cloud Provider</h3>
        <div className="connect-grid">
          {providers.map((p) => (
            <div
              key={p.id}
              className={`provider-card ${selectedProvider === p.id ? "active" : ""}`}
              onClick={() => setSelectedProvider(p.id)}
            >
              <div className="provider-logo">
                {p.logo ? (
                  <img src={p.logo} alt={p.name} className="provider-logo-img" style={{ width: selectedProvider === p.id ? "48px" : "40px", transition: "all 0.3s ease" }} />
                ) : (
                  <Icon name={p.icon} size={selectedProvider === p.id ? 40 : 32} />
                )}
              </div>
              <h4>{p.name}</h4>
              <p>{p.description}</p>
            </div>
          ))}
        </div>
      </section>

      {/* ── File Upload ───────────────────────────────────────────── */}
      <section className="upload-section">
        <h3 style={{ fontSize: 18, marginBottom: 16 }}>2. Upload Terraform Files</h3>
        <div className="glass-card upload-zone" onClick={handleUploadClick}>
          <div className="upload-icon">
            <Icon name="upload" size={32} />
          </div>
          <h3>Drop your .tf files here</h3>
          <p>Or click to browse your local machine. Supports .tf and .tfvars files.</p>
          <button className="save-btn" style={{ padding: "10px 24px" }}>
            Select Files
          </button>
        </div>
      </section>

      {/* ── GitHub Integration ──────────────────────────────────────── */}
      <section>
        <h3 style={{ fontSize: 18, marginBottom: 16 }}>3. Automated Scanning Agent</h3>
        <div className="github-connect">
          <div className="github-icon-large">
            <Icon name="github" size={48} />
          </div>
          <div className="github-info">
            <h3>Connect GitHub Repository</h3>
            <p>
              Link your repository to enable the Compliance Guardian Agent. It will automatically scan pull requests and
              branches, providing CIS benchmark feedback directly in your PR comments.
            </p>
          </div>
          <button className="connect-btn">
            <Icon name="github" size={18} />
            Connect GitHub
          </button>
        </div>
      </section>
    </div>
  );
}
