import { Severity } from "@/lib/types";
import SeverityBadge from "./SeverityBadge";

const ORDER: Severity[] = ["Critical", "High", "Medium", "Low", "Info"];

export default function SummaryBar({
  summary,
}: {
  summary: Record<Severity, number>;
}) {
  return (
    <div className="flex flex-wrap gap-3">
      {ORDER.map((sev) => (
        <div
          key={sev}
          className="flex items-center gap-2 rounded-lg border bg-white px-3 py-2 shadow-sm"
        >
          <SeverityBadge severity={sev} />
          <span className="text-lg font-bold">{summary[sev] ?? 0}</span>
        </div>
      ))}
    </div>
  );
}
