"use client";

export function Logo({ size = 32, className = "", style = {} }) {
  return (
    <span className={`logo-mark ${className}`} style={{ display: "inline-flex", alignItems: "center", justifyContent: "center", lineHeight: 0, ...style }}>
      <svg width={size} height={size} viewBox="0 0 64 64" fill="none" xmlns="http://www.w3.org/2000/svg">
        <defs>
          <linearGradient id="logoGrad1" x1="0%" y1="0%" x2="100%" y2="100%">
            <stop offset="0%" stopColor="#ff7a00" />
            <stop offset="100%" stopColor="#ff9f43" />
          </linearGradient>
          <linearGradient id="logoGrad2" x1="0%" y1="0%" x2="100%" y2="100%">
            <stop offset="0%" stopColor="#ff9f43" />
            <stop offset="100%" stopColor="#ffbe76" />
          </linearGradient>
        </defs>
        {/* Shield body */}
        <path
          d="M32 4L8 16v16c0 14.4 10.24 27.84 24 32 13.76-4.16 24-17.6 24-32V16L32 4z"
          fill="url(#logoGrad1)"
          opacity="0.9"
        />
        {/* Cloud shape inside shield */}
        <path
          d="M40.5 30.5a5.5 5.5 0 00-5.2-3.8 7.5 7.5 0 00-14.3 3.2 4.8 4.8 0 002 9.1h15.5a4.2 4.2 0 002-7.8 5.3 5.3 0 00-.3-.7h.3z"
          fill="white"
          opacity="0.95"
        />
        {/* Checkmark over cloud */}
        <path
          d="M25 32l4.5 4.5L38 28"
          stroke="url(#logoGrad1)"
          strokeWidth="3"
          strokeLinecap="round"
          strokeLinejoin="round"
          fill="none"
        />
        {/* Subtle inner glow ring */}
        <path
          d="M32 8L12 18v14c0 12.4 8.6 23.9 20 27.6 11.4-3.7 20-15.2 20-27.6V18L32 8z"
          fill="none"
          stroke="white"
          strokeWidth="0.8"
          opacity="0.2"
        />
      </svg>
    </span>
  );
}

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
      <svg width={size} height={size} viewBox="0 0 256 153">
        <path d="M72.4 100.6c-29 21.5-71.1 33-107.3 33C-54 133.6-71.8 128-86 118.8c-3-2.1-.3-5 3.3-3.4 18.4 10.7 41 17 64.5 17 15.8 0 33.2-3.3 49.2-10 2.4-1 4.4 1.6 2 3.2h-.6z" fill="#F90" transform="translate(88 10)"/>
        <path d="M80.8 90.6c-4-5.2-26.8-2.5-37-1.3-3.1.4-3.6-2.3-.8-4.3 18.2-12.8 48-9.1 51.5-4.8 3.5 4.3-.9 34.4-18 48.8-2.6 2.2-5.1 1-3.9-1.9 3.8-9.5 12.3-30.8 8.2-36.5z" fill="#F90" transform="translate(88 10)"/>
        <path d="M44.6 18.1V5.6c0-1.9 1.4-3.2 3.2-3.2h56.2c1.8 0 3.2 1.4 3.2 3.2v10.7c0 1.8-1.6 4.2-4.3 7.9l-29.1 41.6c10.8-.3 22.2 1.3 32 6.8 2.2 1.2 2.8 3 3 4.8v13.4c0 1.8-2 3.9-4.1 2.8-17.1-9-39.8-9.9-58.7.1-1.9 1-4.1-.1-4.1-1.9V78.7c0-2 0-5.5 2.1-8.5l33.7-48.3h-29.3c-1.8 0-3.2-1.4-3.2-3.2l-.6-.6z" fill="#252F3E" transform="translate(88 10)"/>
        <path d="M-27.6 93.3h-17.1c-1.6-.1-2.9-1.4-3-2.9V5.8c0-1.7 1.5-3.1 3.3-3.1h15.9c1.6.1 3 1.4 3.1 3V14h.3C-21 4.4-14.4.3-5.8.3 2.9.3 8.2 4.4 12.5 14c4.2-9.6 13.7-13.7 22-13.7 6.3 0 13.2 2.6 17.4 8.4 4.8 6.5 3.8 15.8 3.8 24.1l-.1 57.5c0 1.7-1.5 3.1-3.3 3.1H35.2c-1.7-.1-3.1-1.5-3.1-3.1V40.5c0-3.2.3-11.3-.4-14.4-1.1-5.2-4.3-6.6-8.5-6.6-3.5 0-7.1 2.3-8.6 6-1.5 3.7-1.3 9.8-1.3 14.9v50c0 1.7-1.5 3.1-3.3 3.1h-17.1c-1.7-.1-3.1-1.5-3.1-3.1l-.1-49.9c0-8.5 1.4-21-1-25-1.4-5.2-4.1-6.6-8.2-6.6-3.6 0-7.4 2.4-9 6.2-1.5 3.8-1.3 9.8-1.3 15l.2 50.2c0 1.7-1.5 3.1-3.3 3.1l.3.1z" fill="#252F3E" transform="translate(88 10)"/>
      </svg>
    ),
    azure: (
      <svg width={size} height={size} viewBox="0 0 96 96">
        <defs>
          <linearGradient id="az-a" x1="58.97" x2="37.63" y1="9.01" y2="100.16" gradientUnits="userSpaceOnUse">
            <stop offset="0" stopColor="#114A8B"/>
            <stop offset="1" stopColor="#0669BC"/>
          </linearGradient>
          <linearGradient id="az-b" x1="60" x2="53.37" y1="52.44" y2="54.89" gradientUnits="userSpaceOnUse">
            <stop offset="0" stopOpacity=".3"/>
            <stop offset=".07" stopOpacity=".2"/>
            <stop offset="1" stopOpacity="0"/>
          </linearGradient>
          <linearGradient id="az-c" x1="46.73" x2="73.72" y1="11.42" y2="99.29" gradientUnits="userSpaceOnUse">
            <stop offset="0" stopColor="#3CCBF4"/>
            <stop offset="1" stopColor="#2892DF"/>
          </linearGradient>
        </defs>
        <path fill="url(#az-a)" d="M33.34 6.54h26.04L33.1 89.02a4.33 4.33 0 0 1-4.1 2.97H10.87a4.33 4.33 0 0 1-4.1-5.7L29.24 9.51a4.33 4.33 0 0 1 4.1-2.97z"/>
        <path fill="url(#az-b)" d="M71.17 60.26H29.88a1.98 1.98 0 0 0-1.35 3.43l26.63 24.86a4.36 4.36 0 0 0 2.98 1.18h21.72z"/>
        <path fill="url(#az-c)" d="M33.34 6.54a4.3 4.3 0 0 0-4.13 3.06L6.83 86.19a4.33 4.33 0 0 0 4.07 5.8h18.63a4.47 4.47 0 0 0 3.74-2.86l5.23-15.19 18.68 17.44a4.4 4.4 0 0 0 2.78 1.05h21.6l-9.47-31.62H42.48l17.16-48.4H33.34z"/>
      </svg>
    ),
    gcp: (
      <svg width={size} height={size} viewBox="0 0 24 24">
        <path fill="#EA4335" d="M14.5 6.1h.8l2.3-2.3.1-1C15.7 1 13 0 10 0 6 0 2.6 2.2 1 5.4l2 1.5.3-.1c1-1.8 2.7-3.1 4.7-3.5 2.1-.5 4.3 0 5.9 1.3l.6-.5z"/>
        <path fill="#4285F4" d="M20.3 7.8c-.7-2-2-3.7-3.6-5l-2.8 2.8c1.2.9 2 2.3 2.1 3.8v.5c1.4 0 2.5 1.1 2.5 2.5s-1.1 2.5-2.5 2.5H10l-.5.5v3l.5.5h6c2.8 0 5.2-2.1 5.4-4.9.2-2-.7-3.8-2-5.1l.9-1.1z"/>
        <path fill="#34A853" d="M4 18.9h6v-3H4c-.4 0-.7-.1-1.1-.2l-.7.2L0 18.1l-.2.7C1.3 20.1 2.6 21 4 21l1.1-2.1H4z"/>
        <path fill="#FBBC05" d="M4 7.1C1.2 7.3-1 9.7-.9 12.5c0 1.7.8 3.2 2.1 4.2l2.2-2.2C2.5 13.8 2 12.8 2 11.6c0-1.4 1.1-2.5 2.5-2.5.5 0 .9.1 1.3.4l2.2-2.2C6.8 6.4 5.4 6 4 6v1.1z"/>
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

    "users": (
      <svg width={size} height={size} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round">
        <path d="M17 21v-2a4 4 0 0 0-4-4H5a4 4 0 0 0-4 4v2" />
        <circle cx="9" cy="7" r="4" />
        <path d="M23 21v-2a4 4 0 0 0-3-3.87" />
        <path d="M16 3.13a4 4 0 0 1 0 7.75" />
      </svg>
    ),
    "radar": (
      <svg width={size} height={size} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round">
        <circle cx="12" cy="12" r="10" />
        <circle cx="12" cy="12" r="6" />
        <circle cx="12" cy="12" r="2" />
        <line x1="12" y1="2" x2="12" y2="12" />
      </svg>
    ),
    "download": (
      <svg width={size} height={size} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round">
        <path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4" />
        <polyline points="7 10 12 15 17 10" />
        <line x1="12" y1="15" x2="12" y2="3" />
      </svg>
    ),
    "refresh": (
      <svg width={size} height={size} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round">
        <polyline points="23 4 23 10 17 10" />
        <polyline points="1 20 1 14 7 14" />
        <path d="M3.51 9a9 9 0 0 1 14.85-3.36L23 10M1 14l4.64 4.36A9 9 0 0 0 20.49 15" />
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
    calendar: (
      <svg width={size} height={size} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round">
        <rect x="3" y="4" width="18" height="18" rx="2" /><line x1="16" y1="2" x2="16" y2="6" /><line x1="8" y1="2" x2="8" y2="6" /><line x1="3" y1="10" x2="21" y2="10" />
      </svg>
    ),
    clock: (
      <svg width={size} height={size} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round">
        <circle cx="12" cy="12" r="10" /><polyline points="12 6 12 12 16 14" />
      </svg>
    ),
  };

  return (
    <span className={`icon ${className}`} style={{ display: "inline-flex", alignItems: "center", justifyContent: "center", lineHeight: 0, ...style }}>
      {icons[name] || null}
    </span>
  );
}
