import { Finding, Report, Severity } from "./types";

export interface ReportDiff {
  added: Finding[];
  resolved: Finding[];
  persisting: Finding[];
}

/** Index a report's findings by the stable fingerprint the toolkit emits. */
function byKey(report: Report): Map<string, Finding> {
  const map = new Map<string, Finding>();
  for (const finding of report.findings) {
    if (finding.dedupe_key) map.set(finding.dedupe_key, finding);
  }
  return map;
}

/** Compare two runs: what appeared, what went away, what is still there. */
export function diffReports(older: Report, newer: Report): ReportDiff {
  const before = byKey(older);
  const after = byKey(newer);

  const added: Finding[] = [];
  const persisting: Finding[] = [];
  const resolved: Finding[] = [];

  after.forEach((finding, key) => {
    (before.has(key) ? persisting : added).push(finding);
  });
  before.forEach((finding, key) => {
    if (!after.has(key)) resolved.push(finding);
  });

  return { added, resolved, persisting };
}

export const SEVERITY_ORDER: Severity[] = [
  "Critical",
  "High",
  "Medium",
  "Low",
  "Info",
];

export function isOpen(finding: Finding): boolean {
  return finding.status !== "suppressed";
}

/** Count open findings by an arbitrary key (module, account, region, ...). */
export function groupCount(
  findings: Finding[],
  key: (finding: Finding) => string | null | undefined,
): [string, number][] {
  const counts = new Map<string, number>();
  for (const finding of findings.filter(isOpen)) {
    const bucket = key(finding) || "—";
    counts.set(bucket, (counts.get(bucket) ?? 0) + 1);
  }
  return [...counts.entries()].sort((a, b) => b[1] - a[1]);
}

/** Open counts per severity for a run, used by the trend chart. */
export function severityCounts(report: Report): Record<Severity, number> {
  const counts = {
    Critical: 0,
    High: 0,
    Medium: 0,
    Low: 0,
    Info: 0,
  } as Record<Severity, number>;
  for (const finding of report.findings.filter(isOpen)) {
    counts[finding.severity] += 1;
  }
  return counts;
}

/** Newest last. Runs without a timestamp keep their insertion order. */
export function sortRuns(reports: Report[]): Report[] {
  return [...reports].sort((a, b) =>
    (a.generated_at ?? "").localeCompare(b.generated_at ?? ""),
  );
}
