"use client";

export function Icon({ name, size = 20, className = "", style = {} }) {
  const icons = {
    // ── Sidebar Nav ──────────────────────────────────────────────
    dashboard: (
      <svg width={size} height={size} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round">
        <rect x="3" y="3" width="7" height="7" rx="1.5" />
        <rect x="14" y="3" width="7" height="7" rx="1.5" />
        <rect x="3" y="14" width="7" height="7" rx="1.5" />
        <rect x="14" y="14" width="7" height="7" rx="1.5" />
      </svg>
    ),
    shield: (
      <svg width={size} height={size} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round">
        <path d="M12 2L3.5 6.5V12c0 4.77 3.62 9.23 8.5 10.5 4.88-1.27 8.5-5.73 8.5-10.5V6.5L12 2z" />
      </svg>
    ),
    "shield-check": (
      <svg width={size} height={size} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round">
        <path d="M12 2L3.5 6.5V12c0 4.77 3.62 9.23 8.5 10.5 4.88-1.27 8.5-5.73 8.5-10.5V6.5L12 2z" />
        <path d="M9 12l2 2 4-4" />
      </svg>
    ),
    "chart-line": (
      <svg width={size} height={size} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round">
        <path d="M3 20h18" />
        <path d="M3 17l5-7 4 4 5-8 4 3" />
      </svg>
    ),
    bell: (
      <svg width={size} height={size} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round">
        <path d="M18 8A6 6 0 006 8c0 7-3 9-3 9h18s-3-2-3-9" />
        <path d="M13.73 21a2 2 0 01-3.46 0" />
      </svg>
    ),
    clipboard: (
      <svg width={size} height={size} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round">
        <rect x="8" y="2" width="8" height="4" rx="1" />
        <path d="M16 4h2a2 2 0 012 2v14a2 2 0 01-2 2H6a2 2 0 01-2-2V6a2 2 0 012-2h2" />
        <path d="M12 11h4" /><path d="M12 16h4" /><path d="M8 11h.01" /><path d="M8 16h.01" />
      </svg>
    ),
    gear: (
      <svg width={size} height={size} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round">
        <circle cx="12" cy="12" r="3" />
        <path d="M19.4 15a1.65 1.65 0 00.33 1.82l.06.06a2 2 0 010 2.83 2 2 0 01-2.83 0l-.06-.06a1.65 1.65 0 00-1.82-.33 1.65 1.65 0 00-1 1.51V21a2 2 0 01-2 2 2 2 0 01-2-2v-.09A1.65 1.65 0 009 19.4a1.65 1.65 0 00-1.82.33l-.06.06a2 2 0 01-2.83 0 2 2 0 010-2.83l.06-.06A1.65 1.65 0 004.68 15a1.65 1.65 0 00-1.51-1H3a2 2 0 01-2-2 2 2 0 012-2h.09A1.65 1.65 0 004.6 9a1.65 1.65 0 00-.33-1.82l-.06-.06a2 2 0 010-2.83 2 2 0 012.83 0l.06.06A1.65 1.65 0 009 4.68a1.65 1.65 0 001-1.51V3a2 2 0 012-2 2 2 0 012 2v.09a1.65 1.65 0 001 1.51 1.65 1.65 0 001.82-.33l.06-.06a2 2 0 012.83 0 2 2 0 010 2.83l-.06.06A1.65 1.65 0 0019.32 9a1.65 1.65 0 001.51 1H21a2 2 0 012 2 2 2 0 01-2 2h-.09a1.65 1.65 0 00-1.51 1z" />
      </svg>
    ),
    cloud: (
      <svg width={size} height={size} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round">
        <path d="M18 10a4 4 0 00-3.8-2.8A5.5 5.5 0 003 10.5 3.5 3.5 0 004.5 17h13a3 3 0 001.5-5.6 4 4 0 00-1-1.4z" />
      </svg>
    ),
    "cloud-plus": (
      <svg width={size} height={size} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round">
        <path d="M12 13V19M15 16H9M18 10a4 4 0 00-3.8-2.8A5.5 5.5 0 003 10.5 3.5 3.5 0 004.5 17h13a3 3 0 001.5-5.6 4 4 0 00-1-1.4z" />
      </svg>
    ),
    upload: (
      <svg width={size} height={size} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round">
        <path d="M21 15v4a2 2 0 01-2 2H5a2 2 0 01-2-2v-4" />
        <polyline points="17 8 12 3 7 8" />
        <line x1="12" y1="3" x2="12" y2="15" />
      </svg>
    ),
    github: (
      <svg width={size} height={size} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round">
        <path d="M9 19c-5 1.5-5-2.5-7-3m14 6v-3.87a3.37 3.37 0 00-.94-2.61c3.14-.35 6.44-1.54 6.44-7A5.44 5.44 0 0020 4.77 5.07 5.07 0 0019.91 1S18.73.65 16 2.48a13.38 13.38 0 00-7 0C6.27.65 5.09 1 5.09 1A5.07 5.07 0 005 4.77a5.44 5.44 0 00-1.5 3.78c0 5.42 3.3 6.61 6.44 7A3.37 3.37 0 009 18.13V22" />
      </svg>
    ),
    logout: (
      <svg width={size} height={size} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round">
        <path d="M9 21H5a2 2 0 01-2-2V5a2 2 0 012-2h4" />
        <polyline points="16 17 21 12 16 7" />
        <line x1="21" y1="12" x2="9" y2="12" />
      </svg>
    ),
    aws: (
      <svg width={size} height={size} viewBox="0 0 79 48">
        <path fill="#232F3E" d="M30.7 26.5c0 3.3-1.6 4.7-4.1 4.7-1.6 0-3.3-.6-4.7-1.4v-6.6c1.3-.8 3-.1 4.7-1.4 2.1 0 4.1 1.4 4.1 4.7zm-7.7-14.7c-2.7 1.1-4.1 2.2-4.1 4.4 0 1.7 1.1 3.1 3 3.1 2 0 3.8-1.2 5.1-2.5v-8.3c-1.6 1.1-2.7 2.2-4 3.3zm19 31c-2.4 1.1-5.1 1.7-7.7 1.7-8.8 0-14.1-4.4-14.1-12.7v-2.1c2.1-1.1 4.1-1.7 6.4-1.7 2.4 0 4.7.7 6.8 1.9l.1 4c-1.3-.8-3.1-1.4-5.1-1.4-3.5 0-4.5 2.1-4.5 5 0 2.2.8 4.3 3.1 4.3 1.5 0 2.9-.5 4.1-1.2l.4-6.4c0-4.3 1.9-6.4 5.4-6.4 1.2 0 2.5.2 3.8.7l-.3 3.3c-.9-.4-1.9-.7-2.9-.7-1.5 0-2.3 1.1-2.3 3.1l-.2 9.2c0 1.6.3 3.1.5 4.7h-4s.2-1.1.2-1.3zm18.8-12.8c0 3.1-1.1 4.4-3.6 4.4-1.7 0-3.4-.6-5.1-1.6v-2c1.1.8 2.5 1.4 3.9 1.4 2.2 0 4.9-.7 4.9-4.2V26c-.7 1.1-1.7 1.2-1.7 1.2s-2.7.4-4.2.4c-5.5 0-9.2-2.7-9.2-8.1 0-4.6 2.5-8.4 8.7-8.4 3.5 0 6.1 1.1 8.1 2.5v-1.9c0-4.4 2.8-7.2 9.5-7.2 3.6 0 7.2 1.1 10.3 2.5l-.8 3.6c-2.4-1.1-5.2-1.9-7.7-1.9-3.9 0-5.5 2.7-5.5 7.2v2.5s-2.1-.3-3-.3l-3 .3v-2.5zm-5-.6c0-3.1-.9-4.3-3.1-4.3-1.7 0-3.6.5-5.3 1.5v2c1.2-.8 2.8-1.3 4-1.3 2.2 0 4.4.9 4.4 3.5l.3-.3zM79 42.6c-13.3 5.4-31 7.2-46.1 7.2-21.7 0-41.2-7.2-41.2-7.2.4-.4.8-.8 1.2-1l.7-.3c15 5.4 32.7 7.2 47.3 7.2 13.3 0 26.6-1.5 38.2-5.4 0 0 0-.5-.1-.5zm-44.4-1.6c-1.8 0-3-.4-4.5-1.2-.6-.3-1 .6-.4 1s3.1 1.2 4.9 1.2c2.2 0 4.1-.4 4.1-.4.5-.4.2-1-.1-.6l-4 0z"/>
        <path fill="#FF9900" d="M78 41c-13.3 5.4-31 7.2-46.1 7.2-21.7 0-41.2-7.2-41.2-7.2l.7-1c15 5.4 32.7 7.2 47.3 7.2 13.3 0 26.6-1.5 38.2-5.4 0 0 0-.5-.1-.5l.9-.1c.3.5.3 1.5.3 2z"/>
      </svg>
    ),
    azure: (
      <svg width={size} height={size} viewBox="0 0 72 72">
        <path fill="#0089D6" d="M12.9 61.2L0 41.2l25.8 5.4z"/>
        <path fill="#0072C6" d="M41.8 10.8L12.9 61.2h41.5z"/>
        <path fill="#005A9E" d="M72 61.2L41.8 10.8v41.5z"/>
        <path fill="#50E6FF" d="M25.8 46.6L12.9 61.2s3.6-11.3 12.9-14.6z"/>
      </svg>
    ),
    gcp: (
      <svg width={size} height={size} viewBox="0 0 24 24">
        <path fill="#4285F4" d="M23.6 12.2c0-.8-.1-1.6-.2-2.4H12v4.6h6.5c-.3 1.5-1.1 2.8-2.4 3.6l3.8 3c2.3-2.1 3.7-5.2 3.7-8.8z"/>
        <path fill="#34A853" d="M12 24c3.2 0 5.9-1.1 7.9-2.9l-3.8-2.9c-1.1.7-2.5 1.1-4.1 1.1-3.1 0-5.7-2.1-6.7-4.9l-3.9 3c2 3.9 6 6.6 10.6 6.6z"/>
        <path fill="#FBBC05" d="M5.3 14.4c-.2-.7-.4-1.4-.4-2.2s.2-1.5.4-2.2l-3.9-3C.5 8.9 0 10.4 0 12s.5 3.1 1.4 4.6l3.9-3.2z"/>
        <path fill="#EA4335" d="M12 4.8c1.7 0 3.3.6 4.5 1.8l3.4-3.4C17.9 1.2 15.2 0 12 0 7.4 0 3.4 2.7 1.4 6.6l3.9 3c1-2.8 3.6-4.8 6.7-4.8z"/>
      </svg>
    ),

    // ── Stat Cards ───────────────────────────────────────────────
    folder: (
      <svg width={size} height={size} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round">
        <path d="M22 19a2 2 0 01-2 2H4a2 2 0 01-2-2V5a2 2 0 012-2h5l2 3h9a2 2 0 012 2z" />
      </svg>
    ),
    search: (
      <svg width={size} height={size} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round">
        <circle cx="11" cy="11" r="8" />
        <path d="M21 21l-4.35-4.35" />
      </svg>
    ),
    "circle-check": (
      <svg width={size} height={size} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round">
        <circle cx="12" cy="12" r="10" />
        <path d="M9 12l2 2 4-4" />
      </svg>
    ),

    // ── Severity Indicators ──────────────────────────────────────
    "dot-critical": (
      <svg width={size * 0.6} height={size * 0.6} viewBox="0 0 12 12">
        <circle cx="6" cy="6" r="5" fill="#ef4444" />
      </svg>
    ),
    "dot-high": (
      <svg width={size * 0.6} height={size * 0.6} viewBox="0 0 12 12">
        <circle cx="6" cy="6" r="5" fill="#f97316" />
      </svg>
    ),
    "dot-medium": (
      <svg width={size * 0.6} height={size * 0.6} viewBox="0 0 12 12">
        <circle cx="6" cy="6" r="5" fill="#f59e0b" />
      </svg>
    ),
    "dot-low": (
      <svg width={size * 0.6} height={size * 0.6} viewBox="0 0 12 12">
        <circle cx="6" cy="6" r="5" fill="#6366f1" />
      </svg>
    ),

    // ── Alert Types ──────────────────────────────────────────────
    siren: (
      <svg width={size} height={size} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round">
        <path d="M12 2v4" /><path d="M5.64 5.64l2.83 2.83" /><path d="M18.36 5.64l-2.83 2.83" />
        <path d="M7 14H5" /><path d="M19 14h-2" />
        <circle cx="12" cy="14" r="4" />
        <path d="M8 20h8" />
      </svg>
    ),
    "triangle-alert": (
      <svg width={size} height={size} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round">
        <path d="M10.29 3.86L1.82 18a2 2 0 001.71 3h16.94a2 2 0 001.71-3L13.71 3.86a2 2 0 00-3.42 0z" />
        <line x1="12" y1="9" x2="12" y2="13" />
        <line x1="12" y1="17" x2="12.01" y2="17" />
      </svg>
    ),

    // ── Login / Form ─────────────────────────────────────────────
    envelope: (
      <svg width={size} height={size} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round">
        <rect x="2" y="4" width="20" height="16" rx="2" />
        <path d="M22 7l-10 6L2 7" />
      </svg>
    ),
    lock: (
      <svg width={size} height={size} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round">
        <rect x="3" y="11" width="18" height="11" rx="2" />
        <path d="M7 11V7a5 5 0 0110 0v4" />
      </svg>
    ),
    eye: (
      <svg width={size} height={size} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round">
        <path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z" />
        <circle cx="12" cy="12" r="3" />
      </svg>
    ),
    "eye-off": (
      <svg width={size} height={size} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round">
        <path d="M17.94 17.94A10.07 10.07 0 0112 20c-7 0-11-8-11-8a18.45 18.45 0 015.06-5.94" />
        <path d="M9.9 4.24A9.12 9.12 0 0112 4c7 0 11 8 11 8a18.5 18.5 0 01-2.16 3.19" />
        <path d="M14.12 14.12a3 3 0 11-4.24-4.24" />
        <line x1="1" y1="1" x2="23" y2="23" />
      </svg>
    ),
    wrench: (
      <svg width={size} height={size} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round">
        <path d="M14.7 6.3a1 1 0 000 1.4l1.6 1.6a1 1 0 001.4 0l3.77-3.77a6 6 0 01-7.94 7.94l-6.91 6.91a2.12 2.12 0 01-3-3l6.91-6.91a6 6 0 017.94-7.94l-3.76 3.76z" />
      </svg>
    ),

    // ── Misc ─────────────────────────────────────────────────────
    brain: (
      <svg width={size} height={size} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round">
        <path d="M9.5 2A5.5 5.5 0 005 6a4 4 0 00-1.8 6.8A4.5 4.5 0 006 21h1" />
        <path d="M14.5 2A5.5 5.5 0 0119 6a4 4 0 011.8 6.8A4.5 4.5 0 0118 21h-1" />
        <path d="M12 2v20" />
      </svg>
    ),
    copy: (
      <svg width={size} height={size} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round">
        <rect x="9" y="9" width="13" height="13" rx="2" />
        <path d="M5 15H4a2 2 0 01-2-2V4a2 2 0 012-2h9a2 2 0 012 2v1" />
      </svg>
    ),
    check: (
      <svg width={size} height={size} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round">
        <polyline points="20 6 9 17 4 12" />
      </svg>
    ),
    "arrow-up": (
      <svg width={size} height={size} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
        <path d="M12 19V5" /><path d="M5 12l7-7 7 7" />
      </svg>
    ),
    "arrow-down": (
      <svg width={size} height={size} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
        <path d="M12 5v14" /><path d="M19 12l-7 7-7-7" />
      </svg>
    ),
    server: (
      <svg width={size} height={size} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round">
        <rect x="2" y="2" width="20" height="8" rx="2" />
        <rect x="2" y="14" width="20" height="8" rx="2" />
        <line x1="6" y1="6" x2="6.01" y2="6" /><line x1="6" y1="18" x2="6.01" y2="18" />
      </svg>
    ),
    database: (
      <svg width={size} height={size} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round">
        <ellipse cx="12" cy="5" rx="9" ry="3" />
        <path d="M21 12c0 1.66-4.03 3-9 3s-9-1.34-9-3" />
        <path d="M3 5v14c0 1.66 4.03 3 9 3s9-1.34 9-3V5" />
      </svg>
    ),
    palette: (
      <svg width={size} height={size} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round">
        <circle cx="12" cy="12" r="10" />
        <circle cx="13.5" cy="7.5" r="1.5" fill="currentColor" /><circle cx="17" cy="12" r="1.5" fill="currentColor" />
        <circle cx="8" cy="9" r="1.5" fill="currentColor" /><circle cx="8" cy="15" r="1.5" fill="currentColor" />
      </svg>
    ),
    "file-text": (
      <svg width={size} height={size} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round">
        <path d="M14 2H6a2 2 0 00-2 2v16a2 2 0 002 2h12a2 2 0 002-2V8z" />
        <polyline points="14 2 14 8 20 8" />
        <line x1="16" y1="13" x2="8" y2="13" /><line x1="16" y1="17" x2="8" y2="17" /><polyline points="10 9 9 9 8 9" />
      </svg>
    ),
    sun: (
      <svg width={size} height={size} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
        <circle cx="12" cy="12" r="5" />
        <line x1="12" y1="1" x2="12" y2="3" /><line x1="12" y1="21" x2="12" y2="23" />
        <line x1="4.22" y1="4.22" x2="5.64" y2="5.64" /><line x1="18.36" y1="18.36" x2="19.78" y2="19.78" />
        <line x1="1" y1="12" x2="3" y2="12" /><line x1="21" y1="12" x2="23" y2="12" />
        <line x1="4.22" y1="19.78" x2="5.64" y2="18.36" /><line x1="18.36" y1="5.64" x2="19.78" y2="4.22" />
      </svg>
    ),
    moon: (
      <svg width={size} height={size} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
        <path d="M21 12.79A9 9 0 1 1 11.21 3 7 7 0 0 0 21 12.79z" />
      </svg>
    ),
  };

  return (
    <span className={`icon ${className}`} style={{ display: "inline-flex", alignItems: "center", justifyContent: "center", lineHeight: 0, ...style }}>
      {icons[name] || null}
    </span>
  );
}
