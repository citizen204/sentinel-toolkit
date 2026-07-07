export type Severity = "Critical" | "High" | "Medium" | "Low" | "Info";

export interface Finding {
  id: string;
  module: string;
  severity: Severity;
  title: string;
  description: string;
  remediation: string;
  category?: string | null;
  references?: string[];
  evidence: Record<string, unknown>;
  resource: string | null;
  timestamp: string;
}

export interface Report {
  generated_at: string;
  summary: Record<Severity, number>;
  findings: Finding[];
}
