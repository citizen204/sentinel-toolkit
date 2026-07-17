"use client";

import { ReportDiff } from "@/lib/diff";

export default function DiffPanel({ diff }: { diff: ReportDiff }) {
  const buckets: [string, number, string][] = [
    ["New", diff.added.length, "bg-red-50 text-red-700"],
    ["Resolved", diff.resolved.length, "bg-emerald-50 text-emerald-700"],
    ["Persisting", diff.persisting.length, "bg-slate-100 text-slate-700"],
  ];

  return (
    <div className="rounded-lg border bg-white p-4 shadow-sm">
      <h2 className="text-sm font-semibold text-slate-800">Since the previous run</h2>
      <div className="mt-2 flex flex-wrap gap-2">
        {buckets.map(([label, count, cls]) => (
          <span key={label} className={`rounded px-2 py-1 text-sm ${cls}`}>
            {label}: <b>{count}</b>
          </span>
        ))}
      </div>

      {diff.added.length > 0 && (
        <ul className="mt-3 space-y-1 text-sm">
          {diff.added.slice(0, 8).map((finding, i) => (
            <li key={`${finding.dedupe_key}-${i}`} className="text-slate-700">
              <span className="font-bold text-red-700">+</span> [{finding.severity}]{" "}
              {finding.title}{" "}
              <span className="text-slate-400">{finding.resource}</span>
            </li>
          ))}
        </ul>
      )}
      {diff.resolved.length > 0 && (
        <ul className="mt-2 space-y-1 text-sm">
          {diff.resolved.slice(0, 5).map((finding, i) => (
            <li key={`${finding.dedupe_key}-${i}`} className="text-slate-500">
              <span className="font-bold text-emerald-700">−</span> {finding.title}{" "}
              <span className="text-slate-400">{finding.resource}</span>
            </li>
          ))}
        </ul>
      )}
    </div>
  );
}
