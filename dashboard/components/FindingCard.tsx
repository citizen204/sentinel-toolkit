import { Finding, Severity } from "@/lib/types";
import SeverityBadge from "./SeverityBadge";

const BORDER: Record<Severity, string> = {
  Critical: "border-l-red-900",
  High: "border-l-red-600",
  Medium: "border-l-amber-500",
  Low: "border-l-yellow-500",
  Info: "border-l-blue-600",
};

export default function FindingCard({ finding }: { finding: Finding }) {
  return (
    <div
      className={`rounded-lg border border-l-4 bg-white p-4 shadow-sm ${BORDER[finding.severity]}`}
    >
      <div className="flex flex-wrap items-center gap-2">
        <SeverityBadge severity={finding.severity} />
        <span className="font-semibold">{finding.title}</span>
        <span className="text-xs text-slate-500">
          {finding.module} · {finding.id}
        </span>
        {finding.category && (
          <span className="rounded-full bg-slate-200 px-2 py-0.5 text-xs text-slate-600">
            {finding.category}
          </span>
        )}
      </div>
      <p className="mt-2 text-sm text-slate-700">{finding.description}</p>
      {finding.resource && (
        <p className="mt-1 text-sm">
          Resource:{" "}
          <code className="rounded bg-slate-100 px-1">{finding.resource}</code>
        </p>
      )}
      <p className="mt-2 text-sm text-emerald-700">Fix: {finding.remediation}</p>
      {finding.references && finding.references.length > 0 && (
        <p className="mt-1 text-xs text-slate-500">
          References:{" "}
          {finding.references.map((ref, i) => (
            <span key={ref}>
              {i > 0 && ", "}
              <a href={ref} className="text-blue-600 underline" target="_blank" rel="noreferrer">
                {ref.replace(/^https?:\/\//, "")}
              </a>
            </span>
          ))}
        </p>
      )}
    </div>
  );
}
