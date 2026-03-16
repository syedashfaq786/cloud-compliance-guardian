"use client";
import { useEffect, useRef } from "react";
import { Chart as ChartJS, registerables } from "chart.js";
import { Icon } from "./Icons";

ChartJS.register(...registerables);

export default function TrendChart({ data = null }) {
  const chartRef = useRef(null);
  const chartInstance = useRef(null);

  // Default mock data for demo
  const defaultData = {
    labels: ["Jan 28", "Feb 4", "Feb 11", "Feb 18", "Feb 25", "Mar 4", "Mar 11"],
    critical: [8, 6, 5, 7, 4, 3, 2],
    high: [12, 14, 11, 9, 10, 8, 6],
    medium: [18, 16, 20, 15, 14, 12, 10],
    scores: [62, 68, 70, 72, 76, 82, 87],
  };

  const chartData = data || defaultData;

  useEffect(() => {
    if (!chartRef.current) return;

    if (chartInstance.current) {
      chartInstance.current.destroy();
    }

    const ctx = chartRef.current.getContext("2d");

    // Gradient fills
    const criticalGradient = ctx.createLinearGradient(0, 0, 0, 300);
    criticalGradient.addColorStop(0, "rgba(239, 68, 68, 0.3)");
    criticalGradient.addColorStop(1, "rgba(239, 68, 68, 0.0)");

    const highGradient = ctx.createLinearGradient(0, 0, 0, 300);
    highGradient.addColorStop(0, "rgba(249, 115, 22, 0.2)");
    highGradient.addColorStop(1, "rgba(249, 115, 22, 0.0)");

    const mediumGradient = ctx.createLinearGradient(0, 0, 0, 300);
    mediumGradient.addColorStop(0, "rgba(245, 158, 11, 0.15)");
    mediumGradient.addColorStop(1, "rgba(245, 158, 11, 0.0)");

    chartInstance.current = new ChartJS(ctx, {
      type: "line",
      data: {
        labels: chartData.labels,
        datasets: [
          {
            label: "Critical",
            data: chartData.critical,
            borderColor: "#ef4444",
            backgroundColor: criticalGradient,
            fill: true,
            tension: 0.4,
            pointRadius: 4,
            pointHoverRadius: 6,
            pointBackgroundColor: "#ef4444",
            pointBorderColor: "#0a0e1a",
            pointBorderWidth: 2,
            borderWidth: 2,
          },
          {
            label: "High",
            data: chartData.high,
            borderColor: "#f97316",
            backgroundColor: highGradient,
            fill: true,
            tension: 0.4,
            pointRadius: 4,
            pointHoverRadius: 6,
            pointBackgroundColor: "#f97316",
            pointBorderColor: "#0a0e1a",
            pointBorderWidth: 2,
            borderWidth: 2,
          },
          {
            label: "Medium",
            data: chartData.medium,
            borderColor: "#f59e0b",
            backgroundColor: mediumGradient,
            fill: true,
            tension: 0.4,
            pointRadius: 4,
            pointHoverRadius: 6,
            pointBackgroundColor: "#f59e0b",
            pointBorderColor: "#0a0e1a",
            pointBorderWidth: 2,
            borderWidth: 2,
          },
        ],
      },
      options: {
        responsive: true,
        maintainAspectRatio: false,
        interaction: {
          intersect: false,
          mode: "index",
        },
        plugins: {
          legend: {
            position: "top",
            labels: {
              color: "#94a3b8",
              font: { family: "Inter", size: 11, weight: "600" },
              usePointStyle: true,
              pointStyle: "circle",
              padding: 16,
            },
          },
          tooltip: {
            backgroundColor: "rgba(17, 24, 39, 0.95)",
            titleColor: "#f1f5f9",
            bodyColor: "#94a3b8",
            borderColor: "rgba(99, 102, 241, 0.2)",
            borderWidth: 1,
            cornerRadius: 8,
            padding: 12,
            titleFont: { family: "Inter", size: 13, weight: "600" },
            bodyFont: { family: "Inter", size: 12 },
          },
        },
        scales: {
          x: {
            grid: { color: "rgba(255, 255, 255, 0.03)" },
            ticks: {
              color: "#64748b",
              font: { family: "Inter", size: 11 },
            },
          },
          y: {
            beginAtZero: true,
            grid: { color: "rgba(255, 255, 255, 0.03)" },
            ticks: {
              color: "#64748b",
              font: { family: "Inter", size: 11 },
              stepSize: 5,
            },
          },
        },
        animation: {
          duration: 1200,
          easing: "easeInOutQuart",
        },
      },
    });

    return () => {
      if (chartInstance.current) {
        chartInstance.current.destroy();
      }
    };
  }, [chartData]);

  return (
    <div className="glass-card animate-slide-in stagger-3">
      <div className="card-header">
        <h3><Icon name="chart-line" size={18} style={{ marginRight: 8, verticalAlign: "middle", color: "var(--accent-cyan)" }} /> Violation Trend Analysis</h3>
        <span style={{ fontSize: "12px", color: "var(--text-muted)" }}>Last 7 weeks</span>
      </div>
      <div className="chart-container">
        <canvas ref={chartRef} />
      </div>
    </div>
  );
}
