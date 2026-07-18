import { Finding, Report, ScanCoverage, Severity } from "./types";

export interface ReportDiff {
  added: Finding[];
  resolved: Finding[];
  persisting: Finding[];
  /** Gone from the newer run, but that run never covered them. Status unknown. */
  unassessed: Finding[];
  warnings: string[];
}

/** Index a report's findings by the stable fingerprint the toolkit emits. */
function byKey(report: Report): Map<string, Finding> {
  const map = new Map<string, Finding>();
  for (const finding of report.findings) {
    if (finding.dedupe_key) map.set(finding.dedupe_key, finding);
  }
  return map;
}

/** Whether a run is entitled to an opinion about a finding it did not report. */
function covered(coverage: ScanCoverage, finding: Finding): boolean {
  if (coverage.scanners?.[finding.module] !== "ok") return false;
  if (coverage.rules?.length && !coverage.rules.includes(finding.id)) return false;
  const account = finding.asset?.account_id;
  if (account && coverage.accounts?.length && !coverage.accounts.includes(account)) {
    return false;
  }
  const region =
    finding.asset?.region ?? (finding.evidence?.region as string | undefined);
  if (region && coverage.regions?.length && !coverage.regions.includes(region)) {
    return false;
  }
  return true;
}

/**
 * Compare two runs.
 *
 * A finding missing from the newer run was either fixed or never looked for.
 * Only the first counts as resolved — mirroring `sentinel diff`, so the UI and
 * the CLI cannot tell an operator two different stories.
 */
export function diffReports(older: Report, newer: Report): ReportDiff {
  const before = byKey(older);
  const after = byKey(newer);
  const coverage = newer.coverage;

  const added: Finding[] = [];
  const persisting: Finding[] = [];
  const resolved: Finding[] = [];
  const unassessed: Finding[] = [];
  const warnings: string[] = [];

  after.forEach((finding, key) => {
    (before.has(key) ? persisting : added).push(finding);
  });
  before.forEach((finding, key) => {
    if (after.has(key)) return;
    if (coverage && older.coverage && covered(coverage, finding)) {
      resolved.push(finding);
    } else {
      unassessed.push(finding);
    }
  });

  if (!coverage || !older.coverage) {
    warnings.push(
      "One or both runs predate coverage tracking, so nothing can be confirmed as resolved.",
    );
  }
  if (
    older.ruleset_digest &&
    newer.ruleset_digest &&
    older.ruleset_digest !== newer.ruleset_digest
  ) {
    warnings.push(
      "The rule catalog changed between these runs, so some differences reflect rule changes rather than the estate.",
    );
  }
  if (
    older.config_digest &&
    newer.config_digest &&
    older.config_digest !== newer.config_digest
  ) {
    warnings.push(
      "The configuration changed between these runs, so they may not cover the same scope.",
    );
  }
  const notOk = Object.entries(coverage?.scanners ?? {})
    .filter(([, status]) => status !== "ok")
    .map(([name]) => name);
  if (notOk.length) {
    warnings.push(`The newer run did not fully cover: ${notOk.sort().join(", ")}.`);
  }

  return { added, resolved, persisting, unassessed, warnings };
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
