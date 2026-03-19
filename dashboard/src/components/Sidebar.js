"use client";
import { useState, useEffect } from "react";
import { useRouter } from "next/navigation";
import { Icon } from "./Icons";

export default function Sidebar({ activeTab = "dashboard", onTabChange }) {
  const router = useRouter();

  const navItems = [
    { icon: "dashboard", label: "Dashboard", key: "dashboard" },
    { icon: "cloud-plus", label: "Connect",    key: "connect" },
    { icon: "shield",    label: "Audits",    key: "audits" },
    { icon: "chart-line",label: "Trends",    key: "trends" },
    { icon: "bell",      label: "Drift Alerts", key: "drift" },
    { icon: "clipboard", label: "CIS Rules", key: "rules" },
    { icon: "gear",      label: "Settings",  key: "settings" },
  ];

  const [theme, setTheme] = useState('dark');

  useEffect(() => {
    const savedTheme = localStorage.getItem('theme') || 'dark';
    setTheme(savedTheme);
    document.documentElement.setAttribute('data-theme', savedTheme);
  }, []);

  const toggleTheme = () => {
    const newTheme = theme === 'dark' ? 'light' : 'dark';
    setTheme(newTheme);
    document.documentElement.setAttribute('data-theme', newTheme);
    localStorage.setItem('theme', newTheme);
  };

  const handleLogout = () => {
    router.push("/");
  };

  return (
    <aside className="sidebar">
      <div className="sidebar-logo">
        <h1><Icon name="cloud" size={22} style={{ marginRight: 6, verticalAlign: "middle" }} /> Cloud-Compliance Guardian</h1>
        <span>CIS Benchmark Monitor</span>
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
        <button className="nav-item" onClick={toggleTheme} style={{ width: '100%', border: 'none', background: 'transparent', marginBottom: 8 }}>
          <span className="nav-icon"><Icon name={theme === 'dark' ? 'sun' : 'moon'} size={18} /></span>
          <span>{theme === 'dark' ? 'Light Mode' : 'Dark Mode'}</span>
        </button>
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
