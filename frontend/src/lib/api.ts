// Typed API client. Vite proxies /api/* to the Flask backend on :5000.

export interface StatsResponse {
  totals:   { cves: number; assets: number; alerts: number; reports: number };
  severity: Record<"CRITICAL" | "HIGH" | "MEDIUM" | "LOW" | "UNKNOWN", number>;
  sources:  { source: string; count: number }[];
}

export interface CVE {
  cve_id:         string;
  source:         string;
  severity:       string | null;
  cvss_score:     number | null;
  oem:            string | null;
  product_raw:    string | null;
  product_norm:   string | null;
  version_range:  string | null;
  description:    string | null;
  published_date: string | null;
  fetched_at:     string;
  advisory_url:   string | null;
}

export interface ReportItem {
  cve_id:   string;
  filename: string;
  size:     number;
  modified: string;
}

export interface FofaGPTResult {
  query:         string | null;
  raw_query?:    string | null;
  rationale:     string;
  confidence:    "high" | "medium" | "low";
  valid:         boolean;
  examples_used: {
    nl:         string;
    query:      string;
    cve_id?:    string | null;
    source?:    string;
    similarity: number;
  }[];
}

export interface FofaGPTStats {
  total:    number;
  embedded: number;
  by_source: { source: string; count: number }[];
}

export interface FofaGPTExample {
  cve_id: string | null;
  nl:     string;
  query:  string;
  source: string;
}

export interface EnrichedResult {
  enriched: {
    cve_id:            string;
    affected_versions: string[];
    fixed_versions:    string[];
    products:          string[];
    severity:          string;
    description:       string;
    mitigation:        string | null;
  };
  fofa_query: string | null;
  pdf_path:   string;
}

const headers = { "Content-Type": "application/json" };

export async function fetchStats(): Promise<StatsResponse> {
  const r = await fetch("/api/stats");
  if (!r.ok) throw new Error("Failed to fetch stats");
  return r.json();
}

export async function fetchCVEs(limit = 50): Promise<{ cves: CVE[] }> {
  const r = await fetch(`/api/cves?limit=${limit}`);
  if (!r.ok) throw new Error("Failed to fetch CVEs");
  return r.json();
}

export async function fetchReports(): Promise<{ reports: ReportItem[] }> {
  const r = await fetch("/api/reports");
  if (!r.ok) throw new Error("Failed to fetch reports");
  return r.json();
}

export async function startGeneration(cveId: string): Promise<{ job_id: string; cve_id: string }> {
  const r = await fetch("/api/generate", {
    method: "POST",
    headers,
    body: JSON.stringify({ cve_id: cveId }),
  });
  if (!r.ok) {
    const err = await r.json().catch(() => ({}));
    throw new Error(err.error || "Failed to start generation");
  }
  return r.json();
}

export function downloadUrl(cveId: string): string {
  return `/api/download/${encodeURIComponent(cveId)}`;
}

export async function fofaGptGenerate(prompt: string): Promise<FofaGPTResult> {
  const r = await fetch("/api/fofa-gpt", {
    method: "POST",
    headers,
    body: JSON.stringify({ prompt }),
  });
  if (!r.ok) {
    const err = await r.json().catch(() => ({}));
    throw new Error(err.error || "FofaGPT request failed");
  }
  return r.json();
}

export async function fofaGptStats(): Promise<FofaGPTStats> {
  const r = await fetch("/api/fofa-gpt/stats");
  if (!r.ok) throw new Error("Failed to fetch FofaGPT stats");
  return r.json();
}

export async function fofaGptExamples(): Promise<{ examples: FofaGPTExample[] }> {
  const r = await fetch("/api/fofa-gpt/examples");
  if (!r.ok) throw new Error("Failed to fetch FofaGPT examples");
  return r.json();
}

export interface IngestSummary {
  inserted:    number;
  embedded:    number;
  size_before: number;
  size_after:  number;
  ts:          string;
}

export async function fofaGptIngest(): Promise<IngestSummary> {
  const r = await fetch("/api/fofa-gpt/ingest", { method: "POST" });
  if (!r.ok) {
    const err = await r.json().catch(() => ({}));
    throw new Error(err.error || "Ingest failed");
  }
  return r.json();
}
