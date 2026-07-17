"use client";

import { groupCount } from "@/lib/diff";
import { Finding } from "@/lib/types";

function Breakdown({ title, rows }: { title: string; rows: [string, number][] }) {
  return (
    <div>
      <h3 className="text-xs font-semibold uppercase tracking-wide text-slate-500">
        {title}
      </h3>
      {rows.length === 0 ? (
        <p className="mt-1 text-sm text-slate-400">—</p>
      ) : (
        <ul className="mt-1 space-y-0.5 text-sm">
          {rows.slice(0, 6).map(([label, count]) => (
            <li key={label} className="flex justify-between gap-4">
              <span className="truncate text-slate-700">{label}</span>
              <span className="font-medium text-slate-900">{count}</span>
            </li>
          ))}
        </ul>
      )}
    </div>
  );
}

export default function AggregationPanel({ findings }: { findings: Finding[] }) {
  return (
    <div className="grid gap-4 rounded-lg border bg-white p-4 shadow-sm sm:grid-cols-3">
      <Breakdown title="By module" rows={groupCount(findings, (f) => f.module)} />
      <Breakdown
        title="By account"
        rows={groupCount(findings, (f) => f.asset?.account_id)}
      />
      <Breakdown title="By region" rows={groupCount(findings, (f) => f.asset?.region)} />
    </div>
  );
}
