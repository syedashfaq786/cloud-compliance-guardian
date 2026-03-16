"use client";
import { useState } from "react";
import { useRouter } from "next/navigation";
import { Icon } from "@/components/Icons";

export default function LoginPage() {
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [isLoading, setIsLoading] = useState(false);
  const [showPassword, setShowPassword] = useState(false);
  const router = useRouter();

  const handleSubmit = (e) => {
    if (e && e.preventDefault) e.preventDefault();
    setIsLoading(true);
    // Simulate auth delay
    setTimeout(() => {
      setIsLoading(false);
      router.push("/dashboard");
    }, 800);
  };

  return (
    <div className="login-page">
      {/* Animated background orbs */}
      <div className="login-bg-orb orb-1" />
      <div className="login-bg-orb orb-2" />
      <div className="login-bg-orb orb-3" />

      {/* Grid overlay */}
      <div className="login-grid-overlay" />

      <div className="login-container">
        {/* Left panel — branding */}
        <div className="login-branding">
          <div className="branding-content">
            <div className="branding-icon"><Icon name="cloud" size={48} style={{ color: "var(--accent-cyan)" }} /></div>
            <h1>Cloud-Compliance<br />Guardian</h1>
            <p className="branding-subtitle">
              AI-Powered CIS Benchmark Compliance
            </p>
            <div className="branding-stats">
              <div className="branding-stat">
                <span className="stat-number">22+</span>
                <span className="stat-text">CIS Rules</span>
              </div>
              <div className="branding-divider" />
              <div className="branding-stat">
                <span className="stat-number">Sec-8B</span>
                <span className="stat-text">AI Engine</span>
              </div>
              <div className="branding-divider" />
              <div className="branding-stat">
                <span className="stat-number">100%</span>
                <span className="stat-text">Private</span>
              </div>
            </div>

            <div className="branding-features">
              <div className="feature-item">
                <span className="feature-icon"><Icon name="shield" size={20} style={{ color: "var(--accent-cyan)" }} /></span>
                <div>
                  <strong>Privacy-First</strong>
                  <p>All inference runs on your private infrastructure</p>
                </div>
              </div>
              <div className="feature-item">
                <span className="feature-icon"><Icon name="search" size={20} style={{ color: "var(--accent-purple)" }} /></span>
                <div>
                  <strong>AI-Powered Analysis</strong>
                  <p>Context-aware — not rigid regex rules</p>
                </div>
              </div>
              <div className="feature-item">
                <span className="feature-icon"><Icon name="wrench" size={20} style={{ color: "var(--accent-amber)" }} /></span>
                <div>
                  <strong>Auto-Remediation</strong>
                  <p>Copy-paste HCL fix snippets for every finding</p>
                </div>
              </div>
            </div>
          </div>

          <div className="branding-footer">
            <p>Powered by Cisco Sec-8B · Invecto Technologies</p>
          </div>
        </div>

        {/* Right panel — login form */}
        <div className="login-form-panel">
          <div className="login-form-wrapper">
            <div className="login-form-header">
              <h2>Welcome back</h2>
              <p>Sign in to your compliance dashboard</p>
            </div>

            <div className="login-form">
              <div className="form-group">
                <label htmlFor="email">Email Address</label>
                <div className="input-wrapper">
                  <span className="input-icon"><Icon name="envelope" size={16} /></span>
                  <input
                    id="email"
                    type="email"
                    placeholder="you@company.com"
                    value={email}
                    onChange={(e) => setEmail(e.target.value)}
                    required
                    autoComplete="email"
                  />
                </div>
              </div>

              <div className="form-group">
                <label htmlFor="password">Password</label>
                <div className="input-wrapper">
                  <span className="input-icon"><Icon name="lock" size={16} /></span>
                  <input
                    id="password"
                    type={showPassword ? "text" : "password"}
                    placeholder="••••••••"
                    value={password}
                    onChange={(e) => setPassword(e.target.value)}
                    required
                    autoComplete="current-password"
                  />
                  <button
                    type="button"
                    className="toggle-password"
                    onClick={() => setShowPassword(!showPassword)}
                    aria-label="Toggle password visibility"
                  >
                    <Icon name={showPassword ? "eye-off" : "eye"} size={16} />
                  </button>
                </div>
              </div>

              <div className="form-options">
                <label className="remember-me">
                  <input type="checkbox" />
                  <span className="checkbox-custom" />
                  <span>Remember me</span>
                </label>
                <a href="#" className="forgot-link">Forgot password?</a>
              </div>

              <button
                type="button"
                className={`login-btn ${isLoading ? "loading" : ""}`}
                disabled={isLoading}
                onClick={handleSubmit}
              >
                {isLoading ? (
                  <span className="btn-loader">
                    <span className="spinner" />
                    Authenticating...
                  </span>
                ) : (
                  "Sign In"
                )}
              </button>

              <div className="divider-row">
                <span className="divider-line" />
                <span className="divider-text">or continue with</span>
                <span className="divider-line" />
              </div>

              <div className="social-btns">
                <button type="button" className="social-btn">
                  <svg width="18" height="18" viewBox="0 0 24 24" fill="currentColor">
                    <path d="M12 0c-6.626 0-12 5.373-12 12 0 5.302 3.438 9.8 8.207 11.387.599.111.793-.261.793-.577v-2.234c-3.338.726-4.033-1.416-4.033-1.416-.546-1.387-1.333-1.756-1.333-1.756-1.089-.745.083-.729.083-.729 1.205.084 1.839 1.237 1.839 1.237 1.07 1.834 2.807 1.304 3.492.997.107-.775.418-1.305.762-1.604-2.665-.305-5.467-1.334-5.467-5.931 0-1.311.469-2.381 1.236-3.221-.124-.303-.535-1.524.117-3.176 0 0 1.008-.322 3.301 1.23.957-.266 1.983-.399 3.003-.404 1.02.005 2.047.138 3.006.404 2.291-1.552 3.297-1.23 3.297-1.23.653 1.653.242 2.874.118 3.176.77.84 1.235 1.911 1.235 3.221 0 4.609-2.807 5.624-5.479 5.921.43.372.823 1.102.823 2.222v3.293c0 .319.192.694.801.576 4.765-1.589 8.199-6.086 8.199-11.386 0-6.627-5.373-12-12-12z" />
                  </svg>
                  GitHub SSO
                </button>
                <button type="button" className="social-btn">
                  <svg width="18" height="18" viewBox="0 0 24 24" fill="currentColor">
                    <path d="M22.56 12.25c0-.78-.07-1.53-.2-2.25H12v4.26h5.92a5.06 5.06 0 0 1-2.2 3.32v2.77h3.57c2.08-1.92 3.28-4.74 3.28-8.1z" />
                    <path d="M12 23c2.97 0 5.46-.98 7.28-2.66l-3.57-2.77c-.98.66-2.23 1.06-3.71 1.06-2.86 0-5.29-1.93-6.16-4.53H2.18v2.84C3.99 20.53 7.7 23 12 23z" />
                    <path d="M5.84 14.09c-.22-.66-.35-1.36-.35-2.09s.13-1.43.35-2.09V7.07H2.18C1.43 8.55 1 10.22 1 12s.43 3.45 1.18 4.93l2.85-2.22.81-.62z" />
                    <path d="M12 5.38c1.62 0 3.06.56 4.21 1.64l3.15-3.15C17.45 2.09 14.97 1 12 1 7.7 1 3.99 3.47 2.18 7.07l3.66 2.84c.87-2.6 3.3-4.53 6.16-4.53z" />
                  </svg>
                  Google SSO
                </button>
              </div>
            </div>

            <p className="signup-prompt">
              Don&apos;t have an account? <a href="#">Request Access</a>
            </p>
          </div>
        </div>
      </div>
    </div>
  );
}
