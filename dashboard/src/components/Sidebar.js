"use client";
import { useEffect } from "react";
import { useRouter } from "next/navigation";
import { Icon, Logo } from "./Icons";

export default function Sidebar({ activeTab = "dashboard", onTabChange }) {
  const router = useRouter();

  const navItems = [
    { icon: "dashboard", label: "Dashboard", key: "dashboard" },
    { icon: "cloud-plus", label: "Connect",    key: "connect" },
    { icon: "radar",     label: "Monitoring", key: "monitoring" },
    { icon: "topology",  label: "Topology",   key: "topology" },
    { icon: "shield",    label: "Audits",    key: "audits" },
{ icon: "bell",      label: "Drift Alerts", key: "drift" },
    { icon: "clipboard", label: "Compliance Rules", key: "rules" },
    { icon: "gear",      label: "Settings",  key: "settings" },
  ];

  useEffect(() => {
    const savedTheme = localStorage.getItem('theme') || 'light';
    document.documentElement.setAttribute('data-theme', savedTheme);
  }, []);

  const handleLogout = () => {
    router.push("/");
  };

  return (
    <aside className="sidebar">
      <div className="sidebar-logo">
        <div style={{ display: "flex", alignItems: "center", gap: 10 }}>
          <div style={{ width: 44, height: 44, borderRadius: 12, background: "rgba(255,159,67,0.14)", border: "1px solid rgba(255,159,67,0.28)", display: "flex", alignItems: "center", justifyContent: "center", flexShrink: 0, boxShadow: "0 0 16px rgba(255,159,67,0.15)" }}>
            <Logo size={26} />
          </div>
          <div style={{ minWidth: 0 }}>
            <div style={{ fontSize: 18, fontWeight: 900, color: "#fff", lineHeight: 1.2, letterSpacing: "-0.4px" }}>Invecto</div>
            <div style={{ fontSize: 11, fontWeight: 700, color: "rgba(255,159,67,0.9)", letterSpacing: "0.04em", textTransform: "uppercase", lineHeight: 1.3, whiteSpace: "nowrap" }}>Compliance Guard</div>
          </div>
        </div>
        <span style={{ marginTop: 8, display: "block", fontSize: 10, color: "rgba(255,255,255,0.35)", letterSpacing: "0.03em", fontWeight: 500 }}>AI-Powered Cloud &amp; Container Security</span>
      </div>

      <nav className="sidebar-nav">
        {navItems.map((item) => (
          <div
            key={item.key}
            className={`nav-item ${activeTab === item.key ? "active" : ""}`}
            onClick={() => onTabChange && onTabChange(item.key)}
          >
            <span className="nav-icon"><Icon name={item.icon} size={18} /></span>
            <span>{item.label}</span>
          </div>
        ))}
      </nav>

      <div className="sidebar-footer">
        <button className="logout-btn" onClick={handleLogout}>
          <Icon name="logout" size={16} />
          <span>Sign Out</span>
        </button>
        <p>Powered by Cisco Sec-8B</p>
        <p>v1.0.0</p>
      </div>
    </aside>
  );
}
