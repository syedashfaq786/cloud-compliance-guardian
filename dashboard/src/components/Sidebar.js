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
        <h1><Logo size={28} style={{ marginRight: 8, verticalAlign: "middle" }} /> Cloud Compliance Guardian</h1>
        <span>CIS & NIST Compliance Monitor</span>
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
