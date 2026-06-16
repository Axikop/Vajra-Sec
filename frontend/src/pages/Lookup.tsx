import { useEffect, useRef, useState } from "react";
import {
  Search, Play, Download, Copy, Terminal, Sparkles,
  CheckCircle2, AlertCircle, ChevronRight, Loader2,
} from "lucide-react";
import { Card, CardHeader, CardTitle, CardDescription, CardContent } from "@/components/ui/Card";
import { Badge, severityVariant } from "@/components/ui/Badge";
import { Button } from "@/components/ui/Button";
import { Input } from "@/components/ui/Input";
import { startGeneration, downloadUrl, EnrichedResult } from "@/lib/api";
import { cn } from "@/lib/utils";

type LogKind = "info" | "ok" | "warn" | "err" | "fofa";

interface LogLine {
  text: string;
  kind: LogKind;
  ts:   number;
}

export default function Lookup() {
  const [cveId, setCveId] = useState("");
  const [running, setRunning] = useState(false);
  const [logs, setLogs] = useState<LogLine[]>([]);
  const [result, setResult] = useState<EnrichedResult | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [readyCveId, setReadyCveId] = useState<string | null>(null);
  const logsEndRef = useRef<HTMLDivElement>(null);
  const esRef = useRef<EventSource | null>(null);

  useEffect(() => {
    return () => esRef.current?.close();
  }, []);

  useEffect(() => {
    logsEndRef.current?.scrollIntoView({ behavior: "smooth" });
  }, [logs]);

  function addLog(text: string, kind: LogKind = "info") {
    setLogs((prev) => [...prev, { text, kind, ts: Date.now() }]);
  }

  async function onGenerate() {
    const id = cveId.trim().toUpperCase();
    if (!/^CVE-\d{4}-\d+$/.test(id)) {
      setError("Enter a valid CVE ID (e.g. CVE-2024-21762)");
      return;
    }
    setError(null);
    setLogs([]);
    setResult(null);
    setReadyCveId(null);
    setRunning(true);

    try {
      const { job_id } = await startGeneration(id);
      const es = new EventSource(`/api/stream/${job_id}`);
      esRef.current = es;

      es.onmessage = (ev) => {
        const msg = ev.data as string;

        if (msg.startsWith("DONE:ok:")) {
          setReadyCveId(msg.split(":")[2] || id);
          setRunning(false);
          es.close();
          return;
        }
        if (msg.startsWith("DONE:error")) {
          setRunning(false);
          es.close();
          return;
        }
        if (msg.startsWith("RESULT:")) {
          try {
            const parsed = JSON.parse(msg.slice(7)) as EnrichedResult;
            setResult(parsed);
          } catch {
            /* ignore malformed RESULT */
          }
          return;
        }

        let kind: LogKind = "info";
        if (msg.startsWith("[+]")) kind = "ok";
        else if (msg.startsWith("[!]")) kind = "err";
        else if (msg.startsWith("[*]")) kind = "info";
        if (msg.includes("FOFA:")) kind = "fofa";
        addLog(msg, kind);
      };

      es.onerror = () => {
        addLog("[!] Stream error — connection lost", "err");
        setRunning(false);
        es.close();
      };
    } catch (e: any) {
      setError(e.message || "Failed to start enrichment");
      setRunning(false);
    }
  }

  function onCopy(text: string) {
    navigator.clipboard.writeText(text).catch(() => {});
  }

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-2xl font-semibold tracking-tight">CVE Lookup</h1>
        <p className="text-sm text-muted mt-1">
          Run the local enrichment pipeline: web search → article fetch → on-device LLM extraction → FOFA query → PDF.
        </p>
      </div>

      {/* Search bar */}
      <Card>
        <CardContent className="flex flex-col sm:flex-row gap-3 items-stretch sm:items-center">
          <div className="relative flex-1">
            <Search className="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4 text-muted" />
            <Input
              autoFocus
              placeholder="CVE-2024-21762"
              className="pl-9 font-mono"
              value={cveId}
              onChange={(e) => setCveId(e.target.value)}
              onKeyDown={(e) => e.key === "Enter" && !running && onGenerate()}
              disabled={running}
            />
          </div>
          <Button onClick={onGenerate} disabled={running || !cveId.trim()} size="lg">
            {running ? (
              <>
                <Loader2 className="h-4 w-4 animate-spin" /> Running pipeline…
              </>
            ) : (
              <>
                <Play className="h-4 w-4" /> Generate intelligence
              </>
            )}
          </Button>
        </CardContent>
      </Card>

      {error && (
        <div className="flex items-center gap-2 text-sm text-danger px-1">
          <AlertCircle className="h-4 w-4" /> {error}
        </div>
      )}

      <div className="grid grid-cols-1 lg:grid-cols-5 gap-4">
        {/* Live log */}
        <Card className="lg:col-span-3">
          <CardHeader>
            <div className="flex items-center justify-between">
              <div className="flex items-center gap-2">
                <Terminal className="h-4 w-4 text-muted" />
                <CardTitle>Pipeline log</CardTitle>
              </div>
              {running && (
                <Badge variant="info">
                  <span className="h-1.5 w-1.5 rounded-full bg-accent animate-pulse" />
                  streaming
                </Badge>
              )}
            </div>
            <CardDescription>Real-time output streamed from the backend pipeline</CardDescription>
          </CardHeader>
          <CardContent className="p-0">
            <div className="font-mono text-[12.5px] leading-6 p-4 bg-bg/60 max-h-[420px] overflow-y-auto scrollbar-thin">
              {logs.length === 0 ? (
                <div className="text-muted py-8 text-center">
                  <Sparkles className="h-5 w-5 mx-auto mb-2" />
                  Awaiting CVE ID. Try CVE-2024-21762 (FortiOS) or CVE-2024-3400 (PAN-OS).
                </div>
              ) : (
                <>
                  {logs.map((l, i) => (
                    <div key={i} className={cn("whitespace-pre-wrap break-words", logColor(l.kind))}>
                      {l.text}
                    </div>
                  ))}
                  <div ref={logsEndRef} />
                </>
              )}
            </div>
          </CardContent>
        </Card>

        {/* Result panel */}
        <div className="lg:col-span-2 space-y-4">
          <ResultPanel
            result={result}
            ready={!!readyCveId}
            cveId={readyCveId}
            onCopy={onCopy}
          />
        </div>
      </div>
    </div>
  );
}

function logColor(kind: LogKind) {
  switch (kind) {
    case "ok":   return "text-success";
    case "err":  return "text-danger";
    case "warn": return "text-warn";
    case "fofa": return "text-warn font-medium";
    default:     return "text-muted";
  }
}

function ResultPanel({
  result, ready, cveId, onCopy,
}: {
  result: EnrichedResult | null;
  ready: boolean;
  cveId: string | null;
  onCopy: (s: string) => void;
}) {
  if (!result) {
    return (
      <Card>
        <CardHeader>
          <CardTitle>Intelligence summary</CardTitle>
          <CardDescription>
            Structured output from the local LLM appears here as the pipeline runs.
          </CardDescription>
        </CardHeader>
        <CardContent>
          <div className="space-y-3">
            <SkeletonLine width="60%" />
            <SkeletonLine width="40%" />
            <SkeletonLine width="80%" />
            <div className="pt-3 space-y-2">
              <SkeletonLine width="100%" />
              <SkeletonLine width="92%" />
              <SkeletonLine width="70%" />
            </div>
          </div>
        </CardContent>
      </Card>
    );
  }

  const e = result.enriched;
  return (
    <>
      <Card>
        <CardHeader>
          <div className="flex items-start justify-between gap-3">
            <div>
              <CardTitle className="font-mono">{e.cve_id}</CardTitle>
              <CardDescription className="line-clamp-2">{e.description}</CardDescription>
            </div>
            <Badge variant={severityVariant(e.severity)}>{e.severity}</Badge>
          </div>
        </CardHeader>
        <CardContent className="space-y-4 text-sm">
          <Field label="Products">
            <div className="flex flex-wrap gap-1.5">
              {(e.products || []).map((p) => (
                <Badge key={p} variant="info">{p}</Badge>
              ))}
              {(!e.products || e.products.length === 0) && <span className="text-muted">—</span>}
            </div>
          </Field>

          <Field label="Affected versions">
            {(e.affected_versions || []).length === 0 ? (
              <span className="text-muted">—</span>
            ) : (
              <ul className="space-y-1">
                {e.affected_versions.map((v, i) => (
                  <li key={i} className="text-text font-mono text-[12.5px] flex items-center gap-2">
                    <ChevronRight className="h-3 w-3 text-muted shrink-0" />
                    {v}
                  </li>
                ))}
              </ul>
            )}
          </Field>

          <Field label="Fixed versions">
            {(e.fixed_versions || []).length === 0 ? (
              <span className="text-muted">—</span>
            ) : (
              <ul className="space-y-1">
                {e.fixed_versions.map((v, i) => (
                  <li key={i} className="text-success font-mono text-[12.5px] flex items-center gap-2">
                    <CheckCircle2 className="h-3 w-3 shrink-0" />
                    {v}
                  </li>
                ))}
              </ul>
            )}
          </Field>

          {e.mitigation && (
            <Field label="Mitigation">
              <p className="text-text/90 leading-relaxed">{e.mitigation}</p>
            </Field>
          )}
        </CardContent>
      </Card>

      <Card>
        <CardHeader>
          <CardTitle>FOFA reconnaissance query</CardTitle>
          <CardDescription>
            Validated query targeting Indian critical infrastructure
          </CardDescription>
        </CardHeader>
        <CardContent>
          {result.fofa_query ? (
            <div className="space-y-3">
              <pre className="font-mono text-[12.5px] bg-bg/70 border border-border rounded-md p-3 overflow-x-auto scrollbar-thin text-warn whitespace-pre-wrap break-all">
                {result.fofa_query}
              </pre>
              <div className="flex gap-2">
                <Button size="sm" variant="secondary" onClick={() => onCopy(result.fofa_query!)}>
                  <Copy className="h-3.5 w-3.5" /> Copy
                </Button>
                <a
                  href={`https://en.fofa.info/result?qbase64=${btoa(result.fofa_query)}`}
                  target="_blank"
                  rel="noreferrer"
                >
                  <Button size="sm" variant="ghost">
                    Open in FOFA <ChevronRight className="h-3.5 w-3.5" />
                  </Button>
                </a>
              </div>
            </div>
          ) : (
            <div className="text-sm text-muted">No FOFA query generated.</div>
          )}
        </CardContent>
      </Card>

      {ready && cveId && (
        <Card className="border-success/40 bg-success/5">
          <CardContent className="flex items-center justify-between">
            <div className="flex items-center gap-3">
              <div className="h-9 w-9 rounded-md bg-success/15 grid place-items-center text-success">
                <CheckCircle2 className="h-4 w-4" />
              </div>
              <div>
                <div className="text-sm font-medium">Report ready</div>
                <div className="text-[11px] text-muted">{cveId}_report.pdf</div>
              </div>
            </div>
            <a href={downloadUrl(cveId)} target="_blank" rel="noreferrer">
              <Button>
                <Download className="h-4 w-4" /> Download
              </Button>
            </a>
          </CardContent>
        </Card>
      )}
    </>
  );
}

function Field({ label, children }: { label: string; children: React.ReactNode }) {
  return (
    <div>
      <div className="text-[10px] uppercase tracking-wide text-muted mb-1.5">{label}</div>
      <div>{children}</div>
    </div>
  );
}

function SkeletonLine({ width = "100%" }: { width?: string }) {
  return <div className="h-3 bg-elev rounded animate-pulse" style={{ width }} />;
}
