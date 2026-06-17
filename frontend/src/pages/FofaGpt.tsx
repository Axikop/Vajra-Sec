import { useEffect, useState } from "react";
import {
  Sparkles, Send, Copy, Loader2, ChevronRight,
  AlertCircle, CheckCircle2, Database, ExternalLink, Wand2, RefreshCw,
} from "lucide-react";
import { Card, CardHeader, CardTitle, CardDescription, CardContent } from "@/components/ui/Card";
import { Badge } from "@/components/ui/Badge";
import { Button } from "@/components/ui/Button";
import {
  fofaGptGenerate, fofaGptStats, fofaGptExamples, fofaGptIngest,
  FofaGPTResult, FofaGPTStats, FofaGPTExample, IngestSummary,
} from "@/lib/api";
import { cn } from "@/lib/utils";

const SAMPLE_PROMPTS = [
  "find FortiGate firewalls in India",
  "exposed Roundcube webmail servers",
  "Cisco IOS XE devices running 17.9",
  "Microsoft Exchange servers vulnerable to ProxyShell",
  "Apache Tomcat instances globally",
  "MikroTik routers in BSNL network",
];

export default function FofaGpt() {
  const [prompt, setPrompt] = useState("");
  const [running, setRunning] = useState(false);
  const [result, setResult] = useState<FofaGPTResult | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [stats, setStats] = useState<FofaGPTStats | null>(null);
  const [examples, setExamples] = useState<FofaGPTExample[]>([]);
  const [ingesting, setIngesting] = useState(false);
  const [ingestToast, setIngestToast] = useState<IngestSummary | null>(null);

  async function refreshSidebar() {
    try {
      const [s, e] = await Promise.all([fofaGptStats(), fofaGptExamples()]);
      setStats(s);
      setExamples(e.examples);
    } catch {
      /* ignore — non-fatal */
    }
  }

  async function onIngest() {
    if (ingesting) return;
    setIngesting(true);
    setIngestToast(null);
    try {
      const summary = await fofaGptIngest();
      setIngestToast(summary);
      await refreshSidebar();
      // Auto-dismiss toast after 6 seconds
      setTimeout(() => setIngestToast(null), 6000);
    } catch (e: any) {
      setError(e.message || "Ingest failed");
    } finally {
      setIngesting(false);
    }
  }

  useEffect(() => {
    refreshSidebar();
  }, []);

  async function onGenerate(p?: string) {
    const text = (p ?? prompt).trim();
    if (!text) return;
    setError(null);
    setRunning(true);
    setResult(null);
    if (p) setPrompt(p);
    try {
      const r = await fofaGptGenerate(text);
      setResult(r);
    } catch (e: any) {
      setError(e.message || "Request failed");
    } finally {
      setRunning(false);
    }
  }

  function copy(text: string) {
    navigator.clipboard.writeText(text).catch(() => {});
  }

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-end justify-between gap-4">
        <div>
          <div className="flex items-center gap-2 mb-1">
            <Wand2 className="h-5 w-5 text-accent" />
            <h1 className="text-2xl font-semibold tracking-tight">FofaGPT</h1>
          </div>
          <p className="text-sm text-muted">
            Natural-language to FOFA query, grounded in a verified corpus of fofabot tweets and PDF-derived examples (RAG over local embeddings).
          </p>
        </div>
        <div className="flex items-center gap-3">
          {stats && (
            <div className="flex items-center gap-2 text-[11px] text-muted">
              <Database className="h-3.5 w-3.5" />
              <span>
                {stats.total} examples · {stats.embedded} indexed
              </span>
            </div>
          )}
          <Button
            size="sm"
            variant="secondary"
            onClick={onIngest}
            disabled={ingesting}
            title="Pull the latest fofabot tweets via Nitter RSS and add to the corpus"
          >
            {ingesting ? (
              <>
                <Loader2 className="h-3.5 w-3.5 animate-spin" /> Refreshing…
              </>
            ) : (
              <>
                <RefreshCw className="h-3.5 w-3.5" /> Refresh corpus
              </>
            )}
          </Button>
        </div>
      </div>

      {/* Ingest toast */}
      {ingestToast && (
        <div className="flex items-center gap-3 px-4 py-3 rounded-md border border-success/40 bg-success/5 text-sm">
          <CheckCircle2 className="h-4 w-4 text-success shrink-0" />
          <div className="flex-1">
            <span className="text-text">
              Ingested <span className="font-mono text-success">+{ingestToast.inserted}</span> new fofabot examples,
              <span className="font-mono text-success"> +{ingestToast.embedded}</span> embeddings.
            </span>
            <span className="text-muted ml-2">
              corpus {ingestToast.size_before} → {ingestToast.size_after}
            </span>
          </div>
          <button
            onClick={() => setIngestToast(null)}
            className="text-muted hover:text-text text-xs"
          >
            dismiss
          </button>
        </div>
      )}

      {/* Stats strip */}
      {stats && (
        <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
          <SmallStat label="Total examples" value={stats.total} />
          <SmallStat label="Indexed (RAG)" value={stats.embedded} />
          {stats.by_source.slice(0, 2).map((s) => (
            <SmallStat key={s.source} label={s.source} value={s.count} />
          ))}
        </div>
      )}

      <div className="grid grid-cols-1 lg:grid-cols-5 gap-4">
        {/* Prompt + result */}
        <div className="lg:col-span-3 space-y-4">
          <Card>
            <CardContent className="space-y-3">
              <textarea
                autoFocus
                rows={3}
                placeholder="Describe what you want to find on FOFA — e.g. 'find all Cisco IOS XE devices running version 17.9 in India'"
                className={cn(
                  "w-full bg-surface border border-border rounded-md px-3 py-2 text-sm font-mono",
                  "placeholder:text-muted resize-none",
                  "focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-accent/40 focus-visible:border-accent/60",
                )}
                value={prompt}
                onChange={(e) => setPrompt(e.target.value)}
                onKeyDown={(e) => {
                  if (e.key === "Enter" && (e.metaKey || e.ctrlKey) && !running) {
                    onGenerate();
                  }
                }}
                disabled={running}
              />
              <div className="flex items-center justify-between gap-2">
                <div className="flex flex-wrap gap-1.5">
                  {SAMPLE_PROMPTS.slice(0, 3).map((p) => (
                    <button
                      key={p}
                      onClick={() => onGenerate(p)}
                      disabled={running}
                      className="text-[11px] px-2 py-1 rounded-md border border-border bg-elev/40 hover:bg-elev hover:border-accent/50 text-muted hover:text-text transition-colors disabled:opacity-50"
                    >
                      {p}
                    </button>
                  ))}
                </div>
                <Button onClick={() => onGenerate()} disabled={running || !prompt.trim()}>
                  {running ? (
                    <>
                      <Loader2 className="h-4 w-4 animate-spin" /> Generating…
                    </>
                  ) : (
                    <>
                      <Send className="h-4 w-4" /> Generate query
                    </>
                  )}
                </Button>
              </div>
            </CardContent>
          </Card>

          {error && (
            <div className="flex items-center gap-2 text-sm text-danger px-1">
              <AlertCircle className="h-4 w-4" /> {error}
            </div>
          )}

          {/* Result */}
          {result && (
            <Card>
              <CardHeader>
                <div className="flex items-center justify-between">
                  <div className="flex items-center gap-2">
                    <Sparkles className="h-4 w-4 text-accent" />
                    <CardTitle>FOFA query</CardTitle>
                  </div>
                  <ConfidenceBadge confidence={result.confidence} valid={result.valid} />
                </div>
                {result.rationale && (
                  <CardDescription>{result.rationale}</CardDescription>
                )}
              </CardHeader>
              <CardContent className="space-y-3">
                {result.query ? (
                  <>
                    <pre className="font-mono text-[12.5px] bg-bg/70 border border-border rounded-md p-3 overflow-x-auto scrollbar-thin text-warn whitespace-pre-wrap break-all">
                      {result.query}
                    </pre>
                    <div className="flex flex-wrap gap-2">
                      <Button size="sm" variant="secondary" onClick={() => copy(result.query!)}>
                        <Copy className="h-3.5 w-3.5" /> Copy
                      </Button>
                      <a
                        href={`https://en.fofa.info/result?qbase64=${btoa(result.query)}`}
                        target="_blank"
                        rel="noreferrer"
                      >
                        <Button size="sm" variant="ghost">
                          Open in FOFA <ExternalLink className="h-3.5 w-3.5" />
                        </Button>
                      </a>
                    </div>
                  </>
                ) : (
                  <div className="flex items-start gap-2 text-sm text-muted">
                    <AlertCircle className="h-4 w-4 mt-0.5 shrink-0" />
                    <span>
                      Could not generate a valid query.
                      {result.raw_query && (
                        <>
                          {" "}Raw model output:{" "}
                          <code className="font-mono text-[11.5px] text-warn">{result.raw_query}</code>
                        </>
                      )}
                    </span>
                  </div>
                )}
              </CardContent>
            </Card>
          )}

          {/* Retrieved examples */}
          {result && result.examples_used.length > 0 && (
            <Card>
              <CardHeader>
                <CardTitle>Retrieved examples</CardTitle>
                <CardDescription>
                  These verified (NL → query) pairs from the corpus informed the model. RAG retrieval, ranked by cosine similarity.
                </CardDescription>
              </CardHeader>
              <CardContent className="p-0">
                <ul>
                  {result.examples_used.map((ex, i) => (
                    <li
                      key={i}
                      className="px-5 py-3 border-b border-border/40 last:border-0 hover:bg-elev/40 transition-colors"
                    >
                      <div className="flex items-center justify-between gap-3">
                        <div className="text-[11px] uppercase tracking-wide text-muted flex items-center gap-2">
                          <span className="font-mono text-accent">
                            {ex.similarity.toFixed(3)}
                          </span>
                          <Badge variant="muted">{ex.source}</Badge>
                          {ex.cve_id && (
                            <span className="font-mono text-text">{ex.cve_id}</span>
                          )}
                        </div>
                      </div>
                      <div className="text-sm text-text mt-1">{ex.nl}</div>
                      <pre className="font-mono text-[11.5px] text-muted mt-1 break-all whitespace-pre-wrap">
                        {ex.query}
                      </pre>
                    </li>
                  ))}
                </ul>
              </CardContent>
            </Card>
          )}
        </div>

        {/* Inspiration panel */}
        <div className="lg:col-span-2 space-y-4">
          <Card>
            <CardHeader>
              <CardTitle>Sample prompts</CardTitle>
              <CardDescription>Click any to run</CardDescription>
            </CardHeader>
            <CardContent className="p-0">
              <ul>
                {SAMPLE_PROMPTS.map((p) => (
                  <li key={p}>
                    <button
                      onClick={() => onGenerate(p)}
                      disabled={running}
                      className="w-full text-left px-5 py-3 text-sm border-b border-border/40 last:border-0 hover:bg-elev/40 transition-colors flex items-center justify-between gap-2 disabled:opacity-50"
                    >
                      <span className="text-text">{p}</span>
                      <ChevronRight className="h-3.5 w-3.5 text-muted" />
                    </button>
                  </li>
                ))}
              </ul>
            </CardContent>
          </Card>

          <Card>
            <CardHeader>
              <CardTitle>Live corpus</CardTitle>
              <CardDescription>Recent verified examples — fofabot tweets, PDF reports, seeds</CardDescription>
            </CardHeader>
            <CardContent className="p-0">
              <div className="max-h-[420px] overflow-y-auto scrollbar-thin">
                {examples.length === 0 ? (
                  <div className="px-5 py-8 text-center text-muted text-sm">
                    Loading corpus…
                  </div>
                ) : (
                  <ul>
                    {examples.map((ex, i) => (
                      <li
                        key={i}
                        className="px-5 py-3 border-b border-border/40 last:border-0"
                      >
                        <div className="flex items-center justify-between gap-2 mb-1">
                          <Badge variant={ex.source === "fofabot" ? "info" : "muted"}>
                            {ex.source}
                          </Badge>
                          {ex.cve_id && (
                            <span className="font-mono text-[11px] text-muted">
                              {ex.cve_id}
                            </span>
                          )}
                        </div>
                        <div className="text-[12.5px] text-text/90 line-clamp-2">{ex.nl}</div>
                        <pre className="font-mono text-[11px] text-warn mt-1 break-all whitespace-pre-wrap">
                          {ex.query}
                        </pre>
                      </li>
                    ))}
                  </ul>
                )}
              </div>
            </CardContent>
          </Card>
        </div>
      </div>
    </div>
  );
}

function SmallStat({ label, value }: { label: string; value: number }) {
  return (
    <Card>
      <CardContent className="py-3">
        <div className="text-[10px] uppercase tracking-wide text-muted">{label}</div>
        <div className="text-lg font-semibold mt-0.5">{value.toLocaleString()}</div>
      </CardContent>
    </Card>
  );
}

function ConfidenceBadge({
  confidence, valid,
}: { confidence: "high" | "medium" | "low"; valid: boolean }) {
  if (!valid) {
    return (
      <Badge variant="high">
        <AlertCircle className="h-3 w-3" /> invalid
      </Badge>
    );
  }
  if (confidence === "high") {
    return (
      <Badge variant="low">
        <CheckCircle2 className="h-3 w-3" /> high confidence
      </Badge>
    );
  }
  if (confidence === "medium") {
    return <Badge variant="medium">medium confidence</Badge>;
  }
  return <Badge variant="muted">low confidence</Badge>;
}
