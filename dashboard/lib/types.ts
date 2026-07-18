export type Severity = "Critical" | "High" | "Medium" | "Low" | "Info";

export interface Asset {
  provider: string;
  type: string;
  id: string;
  name?: string | null;
  account_id?: string | null;
  region?: string | null;
  tags?: Record<string, string>;
}

export interface Finding {
  id: string;
  module: string;
  severity: Severity;
  title: string;
  description: string;
  remediation: string;
  category?: string | null;
  references?: string[];
  compliance?: string[];
  api?: string | null;
  rationale?: string | null;
  verify?: string | null;
  confidence?: string;
  status?: string;
  suppression_reason?: string | null;
  asset?: Asset | null;
  dedupe_key?: string;
  evidence: Record<string, unknown>;
  resource: string | null;
  timestamp: string;
}

export type CoverageStatus = "ok" | "error" | "skipped";

export interface ScanCoverage {
  scanners: Record<string, CoverageStatus>;
  accounts: string[];
  regions: string[];
  rules: string[];
}

export interface Report {
  schema_version?: string;
  run_id?: string;
  tool_version?: string;
  generated_at: string;
  ruleset_digest?: string;
  config_digest?: string;
  coverage?: ScanCoverage;
  summary: Record<Severity, number>;
  suppressed?: number;
  findings: Finding[];
}
