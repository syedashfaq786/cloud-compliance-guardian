"use client";
import { useState } from "react";
import { useRouter } from "next/navigation";
import { Icon, Logo } from "@/components/Icons";

// ── Seeded demo credentials ───────────────────────────────────────────────────
const DEMO_USERS = [
  { email: "admin@invecto.com",   password: "Admin@2024",  role: "Admin"    },
  { email: "auditor@invecto.com", password: "Audit@2024",  role: "Auditor"  },
  { email: "demo@invecto.com",    password: "Demo@1234",   role: "Viewer"   },
];


const FRAMEWORKS = ["CIS", "NIST", "CCM", "ISO 27001"];

const FEATURES = [
  {
    icon: "shield",
    color: "#ff9f43",
    title: "Multi-Framework Auditing",
    desc: "CIS, NIST 800-53, CSA CCM & more — one platform",
  },
  {
    icon: "search",
    color: "#8b5cf6",
    title: "Container & Cloud Compliance",
    desc: "Docker, Kubernetes, AWS, Azure & GCP coverage",
  },
  {
    icon: "wrench",
    color: "#22c55e",
    title: "AI-Powered Auto-Remediation",
    desc: "Context-aware fix suggestions — not rigid regex rules",
  },
  {
    icon: "cloud",
    color: "#38bdf8",
    title: "Live Infrastructure Scanning",
    desc: "Real-time visibility across your entire cloud estate",
  },
];

export default function LoginPage() {
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [isLoading, setIsLoading] = useState(false);
  const [showPassword, setShowPassword] = useState(false);
  const [error, setError] = useState("");
  const [activeFramework, setActiveFramework] = useState(0);
  const router = useRouter();

  const handleSubmit = (e) => {
    if (e && e.preventDefault) e.preventDefault();
    setError("");
    const match = DEMO_USERS.find(u => u.email === email.trim() && u.password === password);
    if (!match) {
      setError("Invalid email or password. Please check your credentials and try again.");
      return;
    }
    setIsLoading(true);
    setTimeout(() => {
      setIsLoading(false);
      router.push("/dashboard");
    }, 800);
  };

  return (
    <div style={{ display: "flex", height: "100vh", minHeight: "100vh", overflow: "hidden", fontFamily: "'Inter', sans-serif" }}>

      {/* ── Left — Branding panel ── */}
      <div style={{
        flex: "0 0 45%", maxWidth: 560,
        background: "linear-gradient(160deg, #0d1224 0%, #0a0f1e 100%)",
        borderRight: "1px solid rgba(255,255,255,0.07)",
        padding: "56px 52px",
        display: "flex", flexDirection: "column",
        position: "relative", overflow: "hidden",
      }}>
        {/* Animated background — left panel only */}
        <div style={{ position: "absolute", inset: 0, overflow: "hidden", pointerEvents: "none" }}>
          <div style={{ position: "absolute", width: 700, height: 700, borderRadius: "50%", background: "radial-gradient(circle, rgba(255,159,67,0.13) 0%, transparent 65%)", top: "-20%", left: "-20%", animation: "floatOrb 12s ease-in-out infinite" }} />
          <div style={{ position: "absolute", width: 400, height: 400, borderRadius: "50%", background: "radial-gradient(circle, rgba(139,92,246,0.09) 0%, transparent 65%)", bottom: "-10%", right: "-10%", animation: "floatOrb 16s ease-in-out infinite reverse" }} />
          <div style={{ position: "absolute", inset: 0, backgroundImage: "linear-gradient(rgba(255,255,255,0.022) 1px, transparent 1px), linear-gradient(90deg, rgba(255,255,255,0.022) 1px, transparent 1px)", backgroundSize: "55px 55px" }} />
          {FRAMEWORKS.map((fw, i) => (
            <div key={fw} style={{ position: "absolute", padding: "5px 14px", borderRadius: 999, background: "rgba(255,159,67,0.06)", border: "1px solid rgba(255,159,67,0.14)", color: "rgba(255,159,67,0.45)", fontSize: 11, fontWeight: 700, letterSpacing: "0.08em", animation: `floatOrb ${9 + i * 2}s ease-in-out infinite ${i * 1.5}s`, top: `${12 + i * 20}%`, right: "5%" }}>{fw}</div>
          ))}
        </div>

          {/* Logo + name */}
          <div style={{ display: "flex", alignItems: "center", gap: 14, marginBottom: 36 }}>
            <div style={{ width: 48, height: 48, borderRadius: 14, background: "rgba(255,159,67,0.12)", border: "1px solid rgba(255,159,67,0.25)", display: "flex", alignItems: "center", justifyContent: "center", flexShrink: 0 }}>
              <Logo size={30} />
            </div>
            <div>
              <div style={{ fontSize: 15, fontWeight: 800, color: "#fff", lineHeight: 1.2, letterSpacing: "-0.01em" }}>Invecto</div>
              <div style={{ fontSize: 12, fontWeight: 600, color: "rgba(255,159,67,0.85)", letterSpacing: "0.04em", textTransform: "uppercase" }}>Compliance Guard</div>
            </div>
          </div>

          {/* Headline */}
          <div style={{ marginBottom: 28 }}>
            <h1 style={{ fontSize: 30, fontWeight: 800, color: "#fff", lineHeight: 1.2, letterSpacing: "-0.02em", margin: "0 0 10px" }}>
              Enterprise<br /><span style={{ color: "#ff9f43" }}>Compliance,</span><br />Simplified.
            </h1>
            <p style={{ fontSize: 13.5, color: "rgba(255,255,255,0.45)", lineHeight: 1.6, margin: 0 }}>
              Unified auditing across cloud providers, containers, and IaC — powered by AI.
            </p>
          </div>

          {/* Framework pills */}
          <div style={{ display: "flex", flexWrap: "wrap", gap: 6, marginBottom: 28 }}>
            {["CIS Benchmarks", "NIST 800-53", "CSA CCM", "ISO 27001", "Docker / K8s", "AWS · Azure · GCP"].map((tag) => (
              <span key={tag} style={{ fontSize: 10.5, fontWeight: 700, color: "rgba(255,159,67,0.8)", background: "rgba(255,159,67,0.08)", border: "1px solid rgba(255,159,67,0.18)", borderRadius: 999, padding: "3px 10px", letterSpacing: "0.03em" }}>{tag}</span>
            ))}
          </div>

          {/* Stats row */}
          <div style={{ display: "flex", gap: 0, background: "rgba(255,255,255,0.04)", borderRadius: 14, border: "1px solid rgba(255,255,255,0.07)", overflow: "hidden", marginBottom: 28 }}>
            {[
              { val: "3+", label: "Cloud Providers" },
              { val: "4", label: "Frameworks" },
              { val: "500+", label: "Controls" },
            ].map((s, i) => (
              <div key={s.label} style={{ flex: 1, padding: "14px 10px", textAlign: "center", borderRight: i < 2 ? "1px solid rgba(255,255,255,0.07)" : "none" }}>
                <div style={{ fontSize: 18, fontWeight: 800, color: "#ff9f43", lineHeight: 1 }}>{s.val}</div>
                <div style={{ fontSize: 10, color: "rgba(255,255,255,0.4)", marginTop: 4, fontWeight: 600, textTransform: "uppercase", letterSpacing: "0.05em" }}>{s.label}</div>
              </div>
            ))}
          </div>

          {/* Features list */}
          <div style={{ display: "flex", flexDirection: "column", gap: 16, flex: 1 }}>
            {FEATURES.map((f) => (
              <div key={f.title} style={{ display: "flex", alignItems: "flex-start", gap: 12 }}>
                <div style={{ width: 32, height: 32, borderRadius: 9, background: `${f.color}14`, border: `1px solid ${f.color}28`, display: "flex", alignItems: "center", justifyContent: "center", flexShrink: 0 }}>
                  <Icon name={f.icon} size={15} style={{ color: f.color }} />
                </div>
                <div>
                  <div style={{ fontSize: 12.5, fontWeight: 700, color: "rgba(255,255,255,0.85)", marginBottom: 2 }}>{f.title}</div>
                  <div style={{ fontSize: 11.5, color: "rgba(255,255,255,0.38)", lineHeight: 1.5 }}>{f.desc}</div>
                </div>
              </div>
            ))}
          </div>

          {/* Footer */}
          <div style={{ marginTop: 24, paddingTop: 16, borderTop: "1px solid rgba(255,255,255,0.07)" }}>
            <p style={{ fontSize: 11, color: "rgba(255,255,255,0.25)", margin: 0, letterSpacing: "0.02em" }}>
              Powered by Cisco Sec-8B · Invecto Technologies
            </p>
          </div>
        </div>

        {/* ── Right — Login form ───── */}
        <div style={{
          flex: 1,
          background: "#fff",
          display: "flex", alignItems: "center", justifyContent: "center",
          padding: "44px 48px",
          overflowY: "auto",
          height: "100vh",
        }}>
          <div style={{ width: "100%", maxWidth: 360 }}>
            {/* Header */}
            <div style={{ marginBottom: 32 }}>
              <div style={{ display: "inline-flex", alignItems: "center", gap: 6, padding: "4px 12px", borderRadius: 999, background: "rgba(255,159,67,0.08)", border: "1px solid rgba(255,159,67,0.2)", marginBottom: 16 }}>
                <div style={{ width: 6, height: 6, borderRadius: "50%", background: "#22c55e", boxShadow: "0 0 6px #22c55e" }} />
                <span style={{ fontSize: 11, fontWeight: 700, color: "#ff9f43", letterSpacing: "0.06em", textTransform: "uppercase" }}>Secure Access</span>
              </div>
              <h2 style={{ fontSize: 26, fontWeight: 800, color: "#0d1224", margin: "0 0 6px", letterSpacing: "-0.02em" }}>Welcome back</h2>
              <p style={{ fontSize: 13.5, color: "#64748b", margin: 0 }}>Sign in to your compliance dashboard</p>
            </div>

            {/* Email */}
            <div style={{ marginBottom: 16 }}>
              <label style={{ display: "block", fontSize: 12.5, fontWeight: 700, color: "#374151", marginBottom: 6, letterSpacing: "0.01em" }}>Email Address</label>
              <div style={{ position: "relative" }}>
                <span style={{ position: "absolute", left: 13, top: "50%", transform: "translateY(-50%)", color: "#94a3b8" }}>
                  <Icon name="envelope" size={15} />
                </span>
                <input
                  id="email"
                  type="email"
                  placeholder="you@company.com"
                  value={email}
                  onChange={(e) => setEmail(e.target.value)}
                  onKeyDown={(e) => e.key === "Enter" && handleSubmit(e)}
                  autoComplete="email"
                  style={{
                    width: "100%", boxSizing: "border-box",
                    padding: "11px 14px 11px 40px",
                    border: "1.5px solid #e2e8f0",
                    borderRadius: 10, fontSize: 14, color: "#0d1224",
                    background: "#f8fafc", outline: "none", transition: "border-color 0.2s",
                  }}
                  onFocus={(e) => e.target.style.borderColor = "#ff9f43"}
                  onBlur={(e) => e.target.style.borderColor = "#e2e8f0"}
                />
              </div>
            </div>

            {/* Password */}
            <div style={{ marginBottom: 12 }}>
              <label style={{ display: "block", fontSize: 12.5, fontWeight: 700, color: "#374151", marginBottom: 6, letterSpacing: "0.01em" }}>Password</label>
              <div style={{ position: "relative" }}>
                <span style={{ position: "absolute", left: 13, top: "50%", transform: "translateY(-50%)", color: "#94a3b8" }}>
                  <Icon name="lock" size={15} />
                </span>
                <input
                  id="password"
                  type={showPassword ? "text" : "password"}
                  placeholder="••••••••"
                  value={password}
                  onChange={(e) => setPassword(e.target.value)}
                  onKeyDown={(e) => e.key === "Enter" && handleSubmit(e)}
                  autoComplete="current-password"
                  style={{
                    width: "100%", boxSizing: "border-box",
                    padding: "11px 44px 11px 40px",
                    border: "1.5px solid #e2e8f0",
                    borderRadius: 10, fontSize: 14, color: "#0d1224",
                    background: "#f8fafc", outline: "none", transition: "border-color 0.2s",
                  }}
                  onFocus={(e) => e.target.style.borderColor = "#ff9f43"}
                  onBlur={(e) => e.target.style.borderColor = "#e2e8f0"}
                />
                <button type="button" onClick={() => setShowPassword(!showPassword)} style={{ position: "absolute", right: 13, top: "50%", transform: "translateY(-50%)", background: "none", border: "none", color: "#94a3b8", cursor: "pointer", padding: 0 }}>
                  <Icon name={showPassword ? "eye-off" : "eye"} size={16} />
                </button>
              </div>
            </div>

            {/* Options */}
            <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: 20 }}>
              <label style={{ display: "flex", alignItems: "center", gap: 7, cursor: "pointer", fontSize: 12.5, color: "#374151" }}>
                <input type="checkbox" style={{ width: 14, height: 14, accentColor: "#ff9f43" }} />
                Remember me
              </label>
              <a href="#" style={{ fontSize: 12.5, color: "#ff9f43", fontWeight: 600, textDecoration: "none" }}>Forgot password?</a>
            </div>

            {/* Error */}
            {error && (
              <div style={{ padding: "10px 14px", borderRadius: 9, background: "rgba(239,68,68,0.06)", border: "1px solid rgba(239,68,68,0.22)", color: "#ef4444", fontSize: 12.5, marginBottom: 14 }}>
                {error}
              </div>
            )}

            {/* Sign in button */}
            <button
              id="login-btn"
              type="button"
              disabled={isLoading}
              onClick={handleSubmit}
              style={{
                width: "100%", padding: "13px", borderRadius: 10, border: "none",
                background: isLoading ? "#fed7a0" : "linear-gradient(135deg, #ff9f43 0%, #f97316 100%)",
                color: "#fff", fontSize: 14.5, fontWeight: 700, cursor: isLoading ? "default" : "pointer",
                boxShadow: isLoading ? "none" : "0 4px 20px rgba(255,159,67,0.4)",
                transition: "all 0.25s", letterSpacing: "0.01em",
              }}
              onMouseEnter={(e) => { if (!isLoading) e.currentTarget.style.transform = "translateY(-1px)"; }}
              onMouseLeave={(e) => { e.currentTarget.style.transform = "none"; }}
            >
              {isLoading ? (
                <span style={{ display: "flex", alignItems: "center", justifyContent: "center", gap: 8 }}>
                  <span style={{ width: 16, height: 16, border: "2px solid rgba(255,255,255,0.4)", borderTopColor: "#fff", borderRadius: "50%", display: "inline-block", animation: "spin 0.7s linear infinite" }} />
                  Authenticating...
                </span>
              ) : "Sign In"}
            </button>

            {/* Divider */}
            <div style={{ display: "flex", alignItems: "center", gap: 12, margin: "20px 0" }}>
              <div style={{ flex: 1, height: 1, background: "#e2e8f0" }} />
              <span style={{ fontSize: 12, color: "#94a3b8", fontWeight: 500, whiteSpace: "nowrap" }}>or continue with</span>
              <div style={{ flex: 1, height: 1, background: "#e2e8f0" }} />
            </div>

            {/* SSO buttons */}
            <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 10, marginBottom: 24 }}>
              {[
                {
                  label: "GitHub SSO",
                  icon: <svg width="17" height="17" viewBox="0 0 24 24" fill="#374151"><path d="M12 0c-6.626 0-12 5.373-12 12 0 5.302 3.438 9.8 8.207 11.387.599.111.793-.261.793-.577v-2.234c-3.338.726-4.033-1.416-4.033-1.416-.546-1.387-1.333-1.756-1.333-1.756-1.089-.745.083-.729.083-.729 1.205.084 1.839 1.237 1.839 1.237 1.07 1.834 2.807 1.304 3.492.997.107-.775.418-1.305.762-1.604-2.665-.305-5.467-1.334-5.467-5.931 0-1.311.469-2.381 1.236-3.221-.124-.303-.535-1.524.117-3.176 0 0 1.008-.322 3.301 1.23.957-.266 1.983-.399 3.003-.404 1.02.005 2.047.138 3.006.404 2.291-1.552 3.297-1.23 3.297-1.23.653 1.653.242 2.874.118 3.176.77.84 1.235 1.911 1.235 3.221 0 4.609-2.807 5.624-5.479 5.921.43.372.823 1.102.823 2.222v3.293c0 .319.192.694.801.576 4.765-1.589 8.199-6.086 8.199-11.386 0-6.627-5.373-12-12-12z"/></svg>
                },
                {
                  label: "Google SSO",
                  icon: <svg width="17" height="17" viewBox="0 0 24 24"><path fill="#EA4335" d="M12 5.38c1.62 0 3.06.56 4.21 1.64l3.15-3.15C17.45 2.09 14.97 1 12 1 7.7 1 3.99 3.47 2.18 7.07l3.66 2.84c.87-2.6 3.3-4.53 6.16-4.53z"/><path fill="#4285F4" d="M22.56 12.25c0-.78-.07-1.53-.2-2.25H12v4.26h5.92a5.06 5.06 0 0 1-2.2 3.32v2.77h3.57c2.08-1.92 3.28-4.74 3.28-8.1z"/><path fill="#FBBC05" d="M5.84 14.09c-.22-.66-.35-1.36-.35-2.09s.13-1.43.35-2.09V7.07H2.18C1.43 8.55 1 10.22 1 12s.43 3.45 1.18 4.93l2.85-2.22.81-.62z"/><path fill="#34A853" d="M12 23c2.97 0 5.46-.98 7.28-2.66l-3.57-2.77c-.98.66-2.23 1.06-3.71 1.06-2.86 0-5.29-1.93-6.16-4.53H2.18v2.84C3.99 20.53 7.7 23 12 23z"/></svg>
                }
              ].map(({ label, icon }) => (
                <button key={label} type="button" style={{ display: "flex", alignItems: "center", justifyContent: "center", gap: 8, padding: "10px 14px", borderRadius: 10, background: "#fff", border: "1.5px solid #e2e8f0", fontSize: 13, fontWeight: 600, color: "#374151", cursor: "pointer", transition: "all 0.2s" }}
                  onMouseEnter={(e) => { e.currentTarget.style.background = "#f8fafc"; e.currentTarget.style.borderColor = "#cbd5e1"; }}
                  onMouseLeave={(e) => { e.currentTarget.style.background = "#fff"; e.currentTarget.style.borderColor = "#e2e8f0"; }}>
                  {icon} {label}
                </button>
              ))}
            </div>

            <p style={{ textAlign: "center", fontSize: 12, color: "#94a3b8", margin: 0 }}>
              Protected by enterprise-grade security · Invecto Technologies
            </p>
          </div>
        </div>

      <style>{`
        @keyframes floatOrb {
          0%, 100% { transform: translate(0, 0) scale(1); }
          33% { transform: translate(20px, -15px) scale(1.05); }
          66% { transform: translate(-15px, 10px) scale(0.97); }
        }
        @keyframes spin {
          to { transform: rotate(360deg); }
        }
      `}</style>
    </div>
  );
}
