"use client";

import { useEffect, useMemo, useState } from "react";
import { Report, Severity } from "@/lib/types";
import { diffReports, sortRuns } from "@/lib/diff";
import SummaryBar from "@/components/SummaryBar";
import FindingCard from "@/components/FindingCard";
import UploadReport from "@/components/UploadReport";
import TrendChart from "@/components/TrendChart";
import DiffPanel from "@/components/DiffPanel";
import AggregationPanel from "@/components/AggregationPanel";

const FILTERS: (Severity | "All")[] = [
  "All",
  "Critical",
  "High",
  "Medium",
  "Low",
  "Info",
];

export default function Home() {
  const [runs, setRuns] = useState<Report[]>([]);
  const [error, setError] = useState<string | null>(null);
  const [filter, setFilter] = useState<Severity | "All">("All");

  useEffect(() => {
    fetch("/report.json")
      .then((r) => {
        if (!r.ok) throw new Error(`Failed to load report.json (${r.status})`);
        return r.json();
      })
      .then((data: Report) => setRuns([data]))
      .catch((e) => setError(String(e)));
  }, []);

  const current = runs.length ? runs[runs.length - 1] : null;
  const previous = runs.length > 1 ? runs[runs.length - 2] : null;
  const diff = useMemo(
    () => (previous && current ? diffReports(previous, current) : null),
    [previous, current],
  );

  const findings = useMemo(() => {
    if (!current) return [];
    return filter === "All"
      ? current.findings
      : current.findings.filter((f) => f.severity === filter);
  }, [current, filter]);

  return (
    <main className="mx-auto max-w-4xl p-8">
      <h1 className="text-2xl font-bold">Sentinel Security Dashboard</h1>
      {current && (
        <p className="mt-1 text-sm text-slate-500">
          Generated at {current.generated_at} · {current.findings.length} findings
          {runs.length > 1 ? ` · ${runs.length} runs loaded` : ""}
        </p>
      )}

      <div className="mt-6">
        <UploadReport
          onLoad={(loaded) => {
            setRuns((prev) => sortRuns([...prev, ...loaded]));
            setError(null);
          }}
        />
      </div>

      {error && <p className="mt-6 text-red-600">{error}</p>}

      {current && (
        <>
          <div className="mt-6">
            <SummaryBar summary={current.summary} />
            {current.suppressed ? (
              <p className="mt-2 text-sm text-slate-500">
                {current.suppressed} finding(s) suppressed
              </p>
            ) : null}
          </div>

          {diff && (
            <div className="mt-6">
              <DiffPanel diff={diff} />
            </div>
          )}

          {runs.length > 1 && (
            <div className="mt-6">
              <TrendChart runs={runs} />
            </div>
          )}

          <div className="mt-6">
            <AggregationPanel findings={current.findings} />
          </div>

          <div className="mt-6 flex flex-wrap gap-2">
            {FILTERS.map((s) => (
              <button
                key={s}
                onClick={() => setFilter(s)}
                className={`rounded-full px-3 py-1 text-sm ${
                  filter === s
                    ? "bg-slate-900 text-white"
                    : "border bg-white text-slate-700"
                }`}
              >
                {s}
              </button>
            ))}
          </div>

          <div className="mt-6 space-y-3">
            {findings.map((f, i) => (
              <FindingCard key={`${f.id}-${i}`} finding={f} />
            ))}
            {findings.length === 0 && (
              <p className="text-slate-500">No findings for this severity.</p>
            )}
          </div>
        </>
      )}

      {!current && !error && (
        <p className="mt-6 text-slate-500">Loading report…</p>
      )}
    </main>
  );
}
