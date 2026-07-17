"use client";

import { SEVERITY_ORDER, severityCounts } from "@/lib/diff";
import { Report, Severity } from "@/lib/types";

const COLOR: Record<Severity, string> = {
  Critical: "#7f1d1d",
  High: "#dc2626",
  Medium: "#f59e0b",
  Low: "#eab308",
  Info: "#2563eb",
};

export default function TrendChart({ runs }: { runs: Report[] }) {
  if (runs.length < 2) return null;

  const perRun = runs.map((run) => severityCounts(run));
  const totals = perRun.map((counts) =>
    SEVERITY_ORDER.reduce((sum, sev) => sum + counts[sev], 0),
  );
  const max = Math.max(1, ...totals);
  const barWidth = 28;
  const gap = 16;
  const height = 120;

  return (
    <div className="rounded-lg border bg-white p-4 shadow-sm">
      <h2 className="text-sm font-semibold text-slate-800">Open findings over time</h2>
      <svg
        width={runs.length * (barWidth + gap)}
        height={height + 22}
        className="mt-3"
        role="img"
        aria-label="Open findings per run, stacked by severity"
      >
        {perRun.map((counts, index) => {
          let cursor = height;
          return (
            <g key={index} transform={`translate(${index * (barWidth + gap)},0)`}>
              {SEVERITY_ORDER.map((sev) => {
                const value = counts[sev];
                if (!value) return null;
                const barHeight = (value / max) * (height - 8);
                cursor -= barHeight;
                return (
                  <rect
                    key={sev}
                    x={0}
                    y={cursor}
                    width={barWidth}
                    height={barHeight}
                    fill={COLOR[sev]}
                  >
                    <title>{`${sev}: ${value}`}</title>
                  </rect>
                );
              })}
              <text
                x={barWidth / 2}
                y={height + 15}
                textAnchor="middle"
                fontSize="10"
                fill="#64748b"
              >
                {index + 1}
              </text>
            </g>
          );
        })}
      </svg>
      <p className="mt-1 text-xs text-slate-500">
        Runs 1–{runs.length}, oldest to newest · totals {totals.join(" → ")}
      </p>
    </div>
  );
}
