"use client";

import { useEffect, useMemo, useState } from "react";
import { Report, Severity } from "@/lib/types";
import SummaryBar from "@/components/SummaryBar";
import FindingCard from "@/components/FindingCard";
import UploadReport from "@/components/UploadReport";

const FILTERS: (Severity | "All")[] = [
  "All",
  "Critical",
  "High",
  "Medium",
  "Low",
  "Info",
];

export default function Home() {
  const [report, setReport] = useState<Report | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [filter, setFilter] = useState<Severity | "All">("All");

  useEffect(() => {
    fetch("/report.json")
      .then((r) => {
        if (!r.ok) throw new Error(`Failed to load report.json (${r.status})`);
        return r.json();
      })
      .then((data: Report) => setReport(data))
      .catch((e) => setError(String(e)));
  }, []);

  const findings = useMemo(() => {
    if (!report) return [];
    return filter === "All"
      ? report.findings
      : report.findings.filter((f) => f.severity === filter);
  }, [report, filter]);

  return (
    <main className="mx-auto max-w-4xl p-8">
      <h1 className="text-2xl font-bold">Sentinel Security Dashboard</h1>
      {report && (
        <p className="mt-1 text-sm text-slate-500">
          Generated at {report.generated_at} · {report.findings.length} findings
        </p>
      )}

      <div className="mt-6">
        <UploadReport
          onLoad={(r) => {
            setReport(r);
            setError(null);
          }}
        />
      </div>

      {error && <p className="mt-6 text-red-600">{error}</p>}

      {report && (
        <>
          <div className="mt-6">
            <SummaryBar summary={report.summary} />
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

      {!report && !error && (
        <p className="mt-6 text-slate-500">Loading report…</p>
      )}
    </main>
  );
}
