"use client";
import { useEffect, useState } from "react";

export default function ScoreCard({ score = 78.5 }) {
  const [animatedScore, setAnimatedScore] = useState(0);
  const radius = 75;
  const circumference = 2 * Math.PI * radius;
  const offset = circumference - (animatedScore / 100) * circumference;

  const getGrade = (s) => {
    if (s >= 90) return "A";
    if (s >= 75) return "B";
    if (s >= 60) return "C";
    if (s >= 40) return "D";
    return "F";
  };

  const getLevel = (s) => {
    if (s >= 75) return "good";
    if (s >= 50) return "warn";
    return "bad";
  };

  useEffect(() => {
    let start = 0;
    const duration = 1500;
    const startTime = performance.now();

    const animate = (currentTime) => {
      const elapsed = currentTime - startTime;
      const progress = Math.min(elapsed / duration, 1);
      // Ease out cubic
      const eased = 1 - Math.pow(1 - progress, 3);
      setAnimatedScore(Math.round(eased * score * 10) / 10);
      if (progress < 1) requestAnimationFrame(animate);
    };

    requestAnimationFrame(animate);
  }, [score]);

  const level = getLevel(animatedScore);

  return (
    <div className="glass-card score-gauge animate-slide-in stagger-1">
      <div className="score-ring">
        <svg viewBox="0 0 170 170">
          <defs>
            <linearGradient id="gradientGood" x1="0%" y1="0%" x2="100%" y2="100%">
              <stop offset="0%" stopColor="#10b981" />
              <stop offset="100%" stopColor="#22d3ee" />
            </linearGradient>
            <linearGradient id="gradientWarn" x1="0%" y1="0%" x2="100%" y2="100%">
              <stop offset="0%" stopColor="#f59e0b" />
              <stop offset="100%" stopColor="#f97316" />
            </linearGradient>
            <linearGradient id="gradientBad" x1="0%" y1="0%" x2="100%" y2="100%">
              <stop offset="0%" stopColor="#ef4444" />
              <stop offset="100%" stopColor="#f97316" />
            </linearGradient>
          </defs>
          <circle cx="85" cy="85" r={radius} className="score-ring-bg" />
          <circle
            cx="85"
            cy="85"
            r={radius}
            className={`score-ring-fill ${level}`}
            strokeDasharray={circumference}
            strokeDashoffset={offset}
          />
        </svg>
        <div className="score-center">
          <div className={`score-value ${level}`}>{animatedScore}%</div>
          <div className="score-label">Compliance</div>
        </div>
      </div>
      <div className={`score-grade ${level}`}>Grade {getGrade(score)}</div>
    </div>
  );
}
