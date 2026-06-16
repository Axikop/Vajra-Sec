import { useEffect, useState } from "react";
import { Link } from "react-router-dom";
import {
  AlertTriangle, Database, FileText, Server, ArrowUpRight,
  ShieldAlert, ShieldCheck, ExternalLink,
} from "lucide-react";
import {
  PieChart, Pie, Cell, ResponsiveContainer, Tooltip, Legend,
  BarChart, Bar, XAxis, YAxis, CartesianGrid,
} from "recharts";
import { Card, CardHeader, CardTitle, CardDescription, CardContent } from "@/components/ui/Card";
import { Badge, severityVariant } from "@/components/ui/Badge";
import { Button } from "@/components/ui/Button";
import { fetchStats, fetchCVEs, fetchReports, StatsResponse, CVE, ReportItem, downloadUrl } from "@/lib/api";
import { cn, formatDate } from "@/lib/utils";

const SEVERITY_COLORS: Record<string, string> = {
  CRITICAL: "#dc2626",
  HIGH:     "#ef4444",
  MEDIUM:   "#f59e0b",
  LOW:      "#10b981",
  UNKNOWN:  "#6b7280",
};

export default function Dashboard() {
  const [stats, setStats] = useState<StatsResponse | null>(null);
  const [cves, setCves] = useState<CVE[]>([]);
  const [reports, setReports] = useState<ReportItem[]>([]);
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    let cancelled = false;
    (async () => {
      try {
        const [s, c, r] = await Promise.all([fetchStats(), fetchCVEs(20), fetchReports()]);
        if (cancelled) return;
        setStats(s);
        setCves(c.cves);
        setReports(r.reports);
      } catch (e: any) {
        if (!cancelled) setError(e.message || "Failed to load dashboard");
      } finally {
        if (!cancelled) setLoading(false);
      }
    })();
    return () => { cancelled = true; };
  }, []);

  if (error) {
    return (
      <div className="flex items-center gap-3 text-danger">
        <AlertTriangle className="h-5 w-5" /> {error}
      </div>
    );
  }

  const severityData =
    stats
      ? Object.entries(stats.severity)
          .filter(([, v]) => v > 0)
          .map(([name, value]) => ({ name, value, fill: SEVERITY_COLORS[name] }))
      : [];

  const sourceData = stats?.sources ?? [];

  return (
    <div className="space-y-6">
      {/* Header */}
      <div>
        <h1 className="text-2xl font-semibold tracking-tight">Dashboard</h1>
        <p className="text-sm text-muted mt-1">
          Real-time intelligence on tracked CVEs, asset exposure, and report generation.
        </p>
      </div>

      {/* Stat cards */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
        <StatCard
          icon={<Database className="h-4 w-4" />}
          label="Tracked CVEs"
          value={stats?.totals.cves ?? 0}
          loading={loading}
        />
        <StatCard
          icon={<ShieldAlert className="h-4 w-4 text-critical" />}
          label="Critical / High"
          value={(stats?.severity.CRITICAL ?? 0) + (stats?.severity.HIGH ?? 0)}
          accent="critical"
          loading={loading}
        />
        <StatCard
          icon={<Server className="h-4 w-4 text-accent" />}
          label="Discovered Assets"
          value={stats?.totals.assets ?? 0}
          loading={loading}
        />
        <StatCard
          icon={<FileText className="h-4 w-4 text-success" />}
          label="Reports Generated"
          value={stats?.totals.reports ?? 0}
          loading={loading}
        />
      </div>

      {/* Charts row */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-4">
        <Card className="lg:col-span-1">
          <CardHeader>
            <CardTitle>Severity distribution</CardTitle>
            <CardDescription>Across all tracked CVEs</CardDescription>
          </CardHeader>
          <CardContent>
            <div className="h-64">
              {severityData.length === 0 ? (
                <Empty hint="No CVEs in database yet" />
              ) : (
                <ResponsiveContainer width="100%" height="100%">
                  <PieChart>
                    <Pie
                      data={severityData}
                      dataKey="value"
                      nameKey="name"
                      innerRadius={55}
                      outerRadius={85}
                      strokeWidth={1}
                      stroke="#0b0d10"
                      paddingAngle={2}
                    >
                      {severityData.map((d) => (
                        <Cell key={d.name} fill={d.fill} />
                      ))}
                    </Pie>
                    <Tooltip
                      contentStyle={{
                        background: "#12161c",
                        border: "1px solid #252b35",
                        borderRadius: 8,
                        fontSize: 12,
                      }}
                    />
                    <Legend
                      verticalAlign="bottom"
                      height={28}
                      iconType="circle"
                      wrapperStyle={{ fontSize: 11, color: "#8b95a3" }}
                    />
                  </PieChart>
                </ResponsiveContainer>
              )}
            </div>
          </CardContent>
        </Card>

        <Card className="lg:col-span-2">
          <CardHeader>
            <CardTitle>CVEs by source</CardTitle>
            <CardDescription>NVD, CERT-In, vendor advisories, GitHub, Fofabot, enriched</CardDescription>
          </CardHeader>
          <CardContent>
            <div className="h-64">
              {sourceData.length === 0 ? (
                <Empty hint="Run scrapers to populate" />
              ) : (
                <ResponsiveContainer width="100%" height="100%">
                  <BarChart data={sourceData}>
                    <CartesianGrid strokeDasharray="3 3" stroke="#252b35" vertical={false} />
                    <XAxis
                      dataKey="source"
                      tick={{ fill: "#8b95a3", fontSize: 11 }}
                      axisLine={{ stroke: "#252b35" }}
                      tickLine={false}
                    />
                    <YAxis
                      tick={{ fill: "#8b95a3", fontSize: 11 }}
                      axisLine={{ stroke: "#252b35" }}
                      tickLine={false}
                    />
                    <Tooltip
                      contentStyle={{
                        background: "#12161c",
                        border: "1px solid #252b35",
                        borderRadius: 8,
                        fontSize: 12,
                      }}
                      cursor={{ fill: "rgba(59,130,246,0.08)" }}
                    />
                    <Bar dataKey="count" fill="#3b82f6" radius={[4, 4, 0, 0]} />
                  </BarChart>
                </ResponsiveContainer>
              )}
            </div>
          </CardContent>
        </Card>
      </div>

      {/* Recent CVEs + Reports */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-4">
        <Card className="lg:col-span-2">
          <CardHeader>
            <div className="flex items-center justify-between">
              <div>
                <CardTitle>Recent CVEs</CardTitle>
                <CardDescription>Last 20 ingested across all sources</CardDescription>
              </div>
              <Link to="/lookup">
                <Button size="sm" variant="secondary">
                  Lookup CVE <ArrowUpRight className="h-3.5 w-3.5" />
                </Button>
              </Link>
            </div>
          </CardHeader>
          <CardContent className="p-0">
            <div className="overflow-x-auto scrollbar-thin">
              <table className="w-full text-sm">
                <thead className="text-[11px] uppercase tracking-wide text-muted">
                  <tr className="border-b border-border">
                    <th className="text-left px-5 py-3 font-medium">CVE</th>
                    <th className="text-left px-3 py-3 font-medium">Severity</th>
                    <th className="text-left px-3 py-3 font-medium">CVSS</th>
                    <th className="text-left px-3 py-3 font-medium">Source</th>
                    <th className="text-left px-3 py-3 font-medium">Vendor</th>
                    <th className="text-left px-5 py-3 font-medium">Date</th>
                  </tr>
                </thead>
                <tbody>
                  {loading ? (
                    Array.from({ length: 6 }).map((_, i) => <SkeletonRow key={i} />)
                  ) : cves.length === 0 ? (
                    <tr>
                      <td colSpan={6} className="px-5 py-12">
                        <Empty hint="No CVEs ingested yet" />
                      </td>
                    </tr>
                  ) : (
                    cves.map((c) => (
                      <tr
                        key={`${c.cve_id}-${c.source}`}
                        className="border-b border-border/40 hover:bg-elev/40 transition-colors"
                      >
                        <td className="px-5 py-3 font-mono text-[12.5px]">
                          {c.advisory_url ? (
                            <a
                              className="text-accent hover:underline inline-flex items-center gap-1"
                              href={c.advisory_url}
                              target="_blank"
                              rel="noreferrer"
                            >
                              {c.cve_id}
                              <ExternalLink className="h-3 w-3" />
                            </a>
                          ) : (
                            c.cve_id
                          )}
                        </td>
                        <td className="px-3 py-3">
                          <Badge variant={severityVariant(c.severity)}>
                            {(c.severity || "UNKNOWN").toLowerCase()}
                          </Badge>
                        </td>
                        <td className="px-3 py-3 font-mono text-[12px] text-muted">
                          {c.cvss_score ?? "—"}
                        </td>
                        <td className="px-3 py-3 text-muted">{c.source}</td>
                        <td className="px-3 py-3 text-muted truncate max-w-[180px]">
                          {c.oem || "—"}
                        </td>
                        <td className="px-5 py-3 text-muted whitespace-nowrap">
                          {c.published_date || formatDate(c.fetched_at).split(",")[0]}
                        </td>
                      </tr>
                    ))
                  )}
                </tbody>
              </table>
            </div>
          </CardContent>
        </Card>

        <Card>
          <CardHeader>
            <CardTitle>Recent reports</CardTitle>
            <CardDescription>Generated PDF intelligence reports</CardDescription>
          </CardHeader>
          <CardContent className="p-0">
            <div className="max-h-[500px] overflow-y-auto scrollbar-thin">
              {reports.length === 0 ? (
                <div className="px-5 py-12">
                  <Empty hint="No reports yet — run a CVE Lookup" />
                </div>
              ) : (
                <ul>
                  {reports.slice(0, 12).map((r) => (
                    <li
                      key={r.cve_id}
                      className="flex items-center justify-between gap-3 px-5 py-3 border-b border-border/40 hover:bg-elev/40 transition-colors"
                    >
                      <div className="min-w-0">
                        <div className="font-mono text-[12.5px] truncate">{r.cve_id}</div>
                        <div className="text-[11px] text-muted">{formatDate(r.modified)}</div>
                      </div>
                      <a href={downloadUrl(r.cve_id)} target="_blank" rel="noreferrer">
                        <Button size="sm" variant="ghost">
                          <FileText className="h-3.5 w-3.5" /> PDF
                        </Button>
                      </a>
                    </li>
                  ))}
                </ul>
              )}
            </div>
          </CardContent>
        </Card>
      </div>
    </div>
  );
}

function StatCard({
  icon, label, value, accent, loading,
}: {
  icon: React.ReactNode;
  label: string;
  value: number;
  accent?: "critical" | "accent";
  loading?: boolean;
}) {
  return (
    <Card>
      <CardContent className="flex items-start justify-between">
        <div>
          <div className="text-[11px] uppercase tracking-wide text-muted">{label}</div>
          <div
            className={cn(
              "text-2xl font-semibold mt-1",
              accent === "critical" && "text-critical",
              accent === "accent" && "text-accent",
            )}
          >
            {loading ? <span className="inline-block h-6 w-12 bg-elev rounded animate-pulse" /> : value.toLocaleString()}
          </div>
        </div>
        <div className="h-9 w-9 rounded-md bg-elev grid place-items-center text-muted border border-border">
          {icon}
        </div>
      </CardContent>
    </Card>
  );
}

function SkeletonRow() {
  return (
    <tr className="border-b border-border/40">
      {Array.from({ length: 6 }).map((_, i) => (
        <td key={i} className="px-5 py-3">
          <div className="h-3 bg-elev rounded animate-pulse" />
        </td>
      ))}
    </tr>
  );
}

function Empty({ hint }: { hint: string }) {
  return (
    <div className="h-full grid place-items-center text-center">
      <div>
        <ShieldCheck className="h-8 w-8 mx-auto text-muted mb-2" />
        <div className="text-sm text-muted">{hint}</div>
      </div>
    </div>
  );
}
