import { Severity } from "@/lib/types";

const COLORS: Record<Severity, string> = {
  Critical: "bg-red-900 text-white",
  High: "bg-red-600 text-white",
  Medium: "bg-amber-500 text-white",
  Low: "bg-yellow-500 text-white",
  Info: "bg-blue-600 text-white",
};

export default function SeverityBadge({ severity }: { severity: Severity }) {
  return (
    <span
      className={`inline-block rounded px-2 py-0.5 text-xs font-semibold ${COLORS[severity]}`}
    >
      {severity}
    </span>
  );
}
