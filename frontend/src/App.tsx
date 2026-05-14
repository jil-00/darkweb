import React, { useEffect, useState } from "react";
import {
  Area,
  AreaChart,
  Bar,
  BarChart,
  CartesianGrid,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
} from "recharts";
import { Download, FileText } from "lucide-react";
import { Sidebar } from "./Sidebar";
import { RadialProgressRing } from "./RadialProgressRing";
import { Sparkline } from "./Sparkline";
import * as api from "./api";
import "./index.css";

interface RawDashboardResponse {
  stats?: {
    total_queries?: number;
    total_findings?: number;
    active_alerts?: number;
    average_risk_score?: number;
  };
  trends?: Array<{ date: string; avg_risk: number }>;
  top_sources?: Array<{ source: string; count: number }>;
}

interface DashboardData {
  exposure_trend: Array<{ date: string; exposure: number }>;
  risk_distribution: Array<{ category: string; count: number }>;
  recent_events: Array<{ id: string; title: string; timestamp: string; severity: string }>;
  kpis: {
    total_exposures: number;
    avg_risk_score: number;
    critical_alerts: number;
    query_count: number;
  };
}

interface Alert {
  id: string;
  query: string;
  reason: string;
  risk_score: number;
  status: "open" | "acknowledged";
  created_at?: string;
}

function inferSeverity(score: number): string {
  if (score >= 80) return "critical";
  if (score >= 60) return "high";
  if (score >= 40) return "medium";
  return "low";
}

function riskBadgeClass(level: string): string {
  const normalized = level.toLowerCase();
  if (normalized.includes("critical")) return "risk-badge critical";
  if (normalized.includes("high")) return "risk-badge high";
  if (normalized.includes("medium")) return "risk-badge medium";
  if (normalized.includes("low")) return "risk-badge low";
  return "risk-badge info";
}

function clampScore(value: number): number {
  if (Number.isNaN(value)) return 0;
  return Math.max(0, Math.min(100, value));
}

function normalizeDashboard(raw: RawDashboardResponse, alerts: Alert[]): DashboardData {
  const stats = raw.stats || {};
  const trends = raw.trends || [];
  const topSources = raw.top_sources || [];

  return {
    exposure_trend: trends.map((point) => ({
      date: point.date,
      exposure: point.avg_risk,
    })),
    risk_distribution: topSources.map((source) => ({
      category: source.source,
      count: source.count,
    })),
    recent_events: alerts.slice(0, 8).map((alert) => ({
      id: alert.id,
      title: alert.query,
      timestamp: alert.created_at || new Date().toISOString(),
      severity: inferSeverity(alert.risk_score),
    })),
    kpis: {
      total_exposures: stats.total_findings || 0,
      avg_risk_score: stats.average_risk_score || 0,
      critical_alerts: stats.active_alerts || 0,
      query_count: stats.total_queries || 0,
    },
  };
}

export default function App() {
  const [view, setView] = useState<"dashboard" | "search" | "alerts" | "admin">("dashboard");
  const [loading, setLoading] = useState(false);
  const [sessionReady, setSessionReady] = useState(false);
  const [dashboardData, setDashboardData] = useState<DashboardData | null>(null);
  const [searchQuery, setSearchQuery] = useState("");
  const [unifiedReport, setUnifiedReport] = useState<api.UnifiedIntelligenceReport | null>(null);
  const [alerts, setAlerts] = useState<Alert[]>([]);
  const [exportingPDF, setExportingPDF] = useState(false);
  const [exportingCSV, setExportingCSV] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const initializeSessionAndData = async () => {
    try {
      setLoading(true);
      setError(null);
      setSessionReady(false);

      let token = localStorage.getItem("token") || localStorage.getItem("access_token");
      if (!token) {
        const response = await api.login("analyst@example.com", "ChangeMe123!");
        token = response.access_token;
      }
      localStorage.setItem("token", token);

      const [dashboardResponse, alertRows] = await Promise.all([
        api.fetchDashboard(),
        api.listAlerts(),
      ]);
      const typedAlerts = alertRows as Alert[];
      setAlerts(typedAlerts);
      setDashboardData(normalizeDashboard(dashboardResponse as RawDashboardResponse, typedAlerts));
      setSessionReady(true);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to initialize session");
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    void initializeSessionAndData();
  }, []);

  const getRiskBand = (score: number) => {
    if (score >= 80) return { label: "CRITICAL", tone: "critical", description: "Immediate action required" };
    if (score >= 60) return { label: "HIGH", tone: "high", description: "Review and respond within 24h" };
    if (score >= 40) return { label: "MEDIUM", tone: "medium", description: "Monitor and assess impact" };
    if (score >= 20) return { label: "LOW", tone: "low", description: "Background monitoring" };
    return { label: "INFO", tone: "info", description: "Informational only" };
  };

  const handleSearch = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!searchQuery.trim()) return;

    try {
      setLoading(true);
      setError(null);
      const enriched = await api.unifiedEnrich(searchQuery);
      setUnifiedReport(enriched);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Search failed");
    } finally {
      setLoading(false);
    }
  };

  const downloadBlob = (blob: Blob, filename: string) => {
    const url = window.URL.createObjectURL(blob);
    const link = document.createElement("a");
    link.href = url;
    link.download = filename;
    document.body.appendChild(link);
    link.click();
    link.remove();
    window.URL.revokeObjectURL(url);
  };

  const handleExportPDF = async () => {
    if (!unifiedReport) return;
    try {
      setExportingPDF(true);
      const blob = await api.exportPDF(unifiedReport);
      const safeIOC = unifiedReport.ioc_value.replace(/[^a-zA-Z0-9_.-]/g, "_");
      downloadBlob(blob, `report_${safeIOC}.pdf`);
    } catch (err) {
      setError(err instanceof Error ? err.message : "PDF export failed");
    } finally {
      setExportingPDF(false);
    }
  };

  const handleExportCSV = async () => {
    if (!unifiedReport) return;
    try {
      setExportingCSV(true);
      const blob = await api.exportCSV(unifiedReport);
      const safeIOC = unifiedReport.ioc_value.replace(/[^a-zA-Z0-9_.-]/g, "_");
      downloadBlob(blob, `report_${safeIOC}.csv`);
    } catch (err) {
      setError(err instanceof Error ? err.message : "CSV export failed");
    } finally {
      setExportingCSV(false);
    }
  };

  const ackAlert = async (alertId: string) => {
    try {
      await api.acknowledgeAlert(alertId);
      const updatedAlerts = alerts.map((alert) =>
        alert.id === alertId ? { ...alert, status: "acknowledged" as const } : alert
      );
      setAlerts(updatedAlerts);
      if (dashboardData) {
        setDashboardData({
          ...dashboardData,
          recent_events: dashboardData.recent_events.map((event) =>
            event.id === alertId ? { ...event, severity: "low" } : event
          ),
        });
      }
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to acknowledge alert");
    }
  };

  const handleLogout = () => {
    localStorage.removeItem("token");
    localStorage.removeItem("access_token");
    window.location.href = "/";
  };

  const totalExposures = dashboardData?.kpis.total_exposures ?? 0;
  const averageRiskScore = dashboardData?.kpis.avg_risk_score ?? 0;
  const criticalAlerts = dashboardData?.kpis.critical_alerts ?? 0;
  const queryCount = dashboardData?.kpis.query_count ?? 0;
  const alertPct = clampScore(criticalAlerts * 12.5);
  const queryPct = clampScore(queryCount * 4);
  const hasUnifiedData = Boolean(
    unifiedReport && (
      unifiedReport.sources_queried.length > 0 ||
      unifiedReport.findings.length > 0 ||
      unifiedReport.exposure_score > 0 ||
      unifiedReport.threat_score > 0
    )
  );

  return (
    <>
      <Sidebar view={view} onViewChange={setView} onLogout={handleLogout} />
      <div className="main-content">
        <header className="content-header">
          <div>
            <h1 className="text-2xl font-bold text-ink">RJ Intelligence Platform</h1>
            <p className="text-sm text-steel">Enterprise Threat Investigation Command Center</p>
          </div>
        </header>

        {error && (
          <div className="mx-4 mt-4 rounded-lg bg-red-50 border border-red-200 p-3">
            <p className="text-sm text-red-700">{error}</p>
            <button onClick={() => setError(null)} className="text-xs text-red-600 hover:underline mt-1">
              Dismiss
            </button>
          </div>
        )}

        <div className="content-body">
          {!sessionReady && (
            <article className="chart-container">
              <div className="flex flex-col gap-4 md:flex-row md:items-center md:justify-between">
                <div>
                  <p className="hero-eyebrow">Live intelligence feed</p>
                  <h3 className="panel-title mb-2">Connecting to analysis services</h3>
                  <p className="text-sm text-gray-600 max-w-2xl">
                    {loading
                      ? "Initializing session and loading data..."
                      : error
                        ? "The frontend is up, but the API connection failed. Retry after starting the backend services."
                        : "Session not ready yet."}
                  </p>
                </div>
                <div className="flex items-center gap-3">
                  <span className={`status-chip ${error ? "error" : "success"}`}>
                    {error ? "API unavailable" : "Booting"}
                  </span>
                  <button onClick={() => void initializeSessionAndData()} className="btn btn-primary" disabled={loading}>
                    {loading ? "Retrying..." : "Retry"}
                  </button>
                </div>
              </div>
            </article>
          )}

          {sessionReady && view === "dashboard" && (
            <div className="space-y-6">
              <section className="hero-panel">
                <div className="hero-copy">
                  <p className="hero-eyebrow">Threat operations overview</p>
                  <h2>Enterprise intelligence with faster signal triage</h2>
                  <p>
                    Track exposures, validate findings, and move from alerts to action without losing the full investigation context.
                  </p>
                </div>
                <div className="hero-metrics">
                  <div className="hero-ring-card">
                    <RadialProgressRing value={averageRiskScore} label="Avg risk" color="#EA580C" size={112} />
                    <div className="hero-ring-caption">
                      <span>Risk posture</span>
                      <strong>{averageRiskScore.toFixed(1)}</strong>
                    </div>
                  </div>
                  <div className="hero-stat-grid">
                    <div className="hero-stat">
                      <span className="hero-stat-label">Exposures</span>
                      <span className="hero-stat-value">{totalExposures}</span>
                    </div>
                    <div className="hero-stat">
                      <span className="hero-stat-label">Critical alerts</span>
                      <span className="hero-stat-value">{criticalAlerts}</span>
                    </div>
                    <div className="hero-stat">
                      <span className="hero-stat-label">Queries today</span>
                      <span className="hero-stat-value">{queryCount}</span>
                    </div>
                  </div>
                </div>
              </section>

              <div className="kpi-grid">
                <div className="kpi-card">
                  <div className="kpi-header">
                    <span className="kpi-label">Total Exposures</span>
                    <span className="kpi-change">+12%</span>
                  </div>
                  <div className="kpi-value">{totalExposures}</div>
                  <div className="kpi-mini-layout">
                    <RadialProgressRing value={Math.min(totalExposures, 100)} label="Load" color="#DC2626" size={88} />
                    <div className="kpi-copy">
                      <p>Exposure volume is trending upward; keep validating high-signal items first.</p>
                    </div>
                  </div>
                  <Sparkline
                    data={[
                      { value: 20 },
                      { value: 35 },
                      { value: 28 },
                      { value: 45 },
                      { value: 38 },
                      { value: 52 },
                    ]}
                    dataKey="value"
                    color="#DC2626"
                    height={40}
                  />
                </div>

                <div className="kpi-card">
                  <div className="kpi-header">
                    <span className="kpi-label">Avg Risk Score</span>
                    <span className="kpi-change">-5%</span>
                  </div>
                  <div className="kpi-value">{averageRiskScore.toFixed(1)}</div>
                  <div className="kpi-mini-layout">
                    <RadialProgressRing value={averageRiskScore} label="Score" color="#EA580C" size={88} />
                    <div className="kpi-copy">
                      <p>Use this as the current threat floor for prioritizing the next investigation step.</p>
                    </div>
                  </div>
                  <Sparkline
                    data={[
                      { value: 65 },
                      { value: 58 },
                      { value: 62 },
                      { value: 55 },
                      { value: 48 },
                      { value: 52 },
                    ]}
                    dataKey="value"
                    color="#EA580C"
                    height={40}
                  />
                </div>

                <div className="kpi-card">
                  <div className="kpi-header">
                    <span className="kpi-label">Critical Alerts</span>
                    <span className="kpi-change">0</span>
                  </div>
                  <div className="kpi-value">{criticalAlerts}</div>
                  <div className="kpi-mini-layout">
                    <RadialProgressRing value={alertPct} label="Pressure" color="#DC2626" size={88} />
                    <div className="kpi-copy">
                      <p>Escalation pressure stays low when acknowledgements happen quickly.</p>
                    </div>
                  </div>
                  <Sparkline
                    data={[
                      { value: 2 },
                      { value: 3 },
                      { value: 1 },
                      { value: 4 },
                      { value: 2 },
                      { value: 0 },
                    ]}
                    dataKey="value"
                    color="#DC2626"
                    height={40}
                  />
                </div>

                <div className="kpi-card">
                  <div className="kpi-header">
                    <span className="kpi-label">Queries Today</span>
                    <span className="kpi-change">+32%</span>
                  </div>
                  <div className="kpi-value">{queryCount}</div>
                  <div className="kpi-mini-layout">
                    <RadialProgressRing value={queryPct} label="Velocity" color="#2563EB" size={88} />
                    <div className="kpi-copy">
                      <p>Query throughput gives a quick read on active analyst demand.</p>
                    </div>
                  </div>
                  <Sparkline
                    data={[
                      { value: 8 },
                      { value: 12 },
                      { value: 15 },
                      { value: 20 },
                      { value: 18 },
                      { value: 25 },
                    ]}
                    dataKey="value"
                    color="#2563EB"
                    height={40}
                  />
                </div>
              </div>

              <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
                <article className="chart-container">
                  <h3 className="panel-title mb-4">Exposure Trend</h3>
                  <ResponsiveContainer width="100%" height={300}>
                    <AreaChart data={dashboardData?.exposure_trend || []}>
                      <defs>
                        <linearGradient id="colorExposure" x1="0" y1="0" x2="0" y2="1">
                          <stop offset="5%" stopColor="#DC2626" stopOpacity={0.8} />
                          <stop offset="95%" stopColor="#DC2626" stopOpacity={0} />
                        </linearGradient>
                      </defs>
                      <CartesianGrid strokeDasharray="3 3" stroke="rgba(15,23,42,0.1)" />
                      <XAxis dataKey="date" stroke="#64748B" />
                      <YAxis stroke="#64748B" />
                      <Tooltip contentStyle={{ backgroundColor: "#F8FAFC", border: "1px solid #E2E8F0" }} />
                      <Area type="monotone" dataKey="exposure" stroke="#DC2626" fillOpacity={1} fill="url(#colorExposure)" />
                    </AreaChart>
                  </ResponsiveContainer>
                </article>

                <article className="chart-container">
                  <h3 className="panel-title mb-4">Risk Distribution</h3>
                  <ResponsiveContainer width="100%" height={300}>
                    <BarChart
                      data={dashboardData?.risk_distribution || []}
                      layout="vertical"
                      margin={{ top: 5, right: 30, left: 100, bottom: 5 }}
                    >
                      <CartesianGrid strokeDasharray="3 3" stroke="rgba(15,23,42,0.1)" />
                      <XAxis type="number" stroke="#64748B" />
                      <YAxis type="category" dataKey="category" stroke="#64748B" width={95} />
                      <Tooltip contentStyle={{ backgroundColor: "#F8FAFC", border: "1px solid #E2E8F0" }} />
                      <Bar dataKey="count" fill="#2563EB" radius={[0, 8, 8, 0]} />
                    </BarChart>
                  </ResponsiveContainer>
                </article>
              </div>

              <article className="chart-container">
                <h3 className="panel-title mb-4">Recent Events</h3>
                <div className="space-y-2 max-h-64 overflow-auto">
                  {dashboardData?.recent_events.map((event) => (
                    <div key={event.id} className="rounded-lg border border-gray-200 bg-white p-3 hover:shadow-md transition">
                      <div className="flex items-start justify-between gap-3">
                        <div>
                          <p className="font-semibold text-gray-900">{event.title}</p>
                          <p className="text-xs text-gray-500 mt-1">{new Date(event.timestamp).toLocaleString()}</p>
                        </div>
                        <span className={`px-2 py-1 rounded text-xs font-semibold whitespace-nowrap ${
                          event.severity === "critical" ? "bg-red-100 text-red-700" :
                          event.severity === "high" ? "bg-orange-100 text-orange-700" :
                          event.severity === "medium" ? "bg-yellow-100 text-yellow-700" :
                          "bg-green-100 text-green-700"
                        }`}>
                          {event.severity.toUpperCase()}
                        </span>
                      </div>
                    </div>
                  ))}
                  {!dashboardData?.recent_events.length && (
                    <p className="text-sm text-gray-500 py-4">No recent events</p>
                  )}
                </div>
              </article>
            </div>
          )}

          {sessionReady && view === "search" && (
            <div className="space-y-6">
              <article className="chart-container">
                <h3 className="panel-title mb-4">Intelligence Search</h3>

                <form onSubmit={handleSearch} className="flex gap-2 mb-6 items-stretch">
                  <input
                    type="text"
                    value={searchQuery}
                    onChange={(e) => setSearchQuery(e.target.value)}
                    placeholder="Enter email, domain, phone, or hash..."
                    className="flex-1 min-w-0 input"
                  />
                  <button
                    type="submit"
                    disabled={loading}
                    className="btn btn-primary disabled:opacity-50 shrink-0"
                  >
                    {loading ? "Searching..." : "Search"}
                  </button>
                </form>

                {unifiedReport && (
                  <div className="space-y-5">
                    <section className="rounded-xl border border-slate-200 bg-white p-4">
                      <div className="flex flex-wrap items-center justify-between gap-3">
                        <div>
                          <p className="text-xs uppercase tracking-wide text-slate-500">Investigation Target</p>
                          <h4 className="text-xl font-bold text-slate-900">{unifiedReport.ioc_value}</h4>
                          <p className="text-xs text-slate-500 mt-1">Type: {unifiedReport.ioc_type.toUpperCase()}</p>
                        </div>
                        <div className="flex items-center gap-2">
                          <span className={riskBadgeClass(unifiedReport.risk_level)}>{unifiedReport.risk_level}</span>
                          <span className="rounded-md bg-slate-100 px-3 py-1 text-xs font-semibold text-slate-700">
                            Reputation: {unifiedReport.reputation_status}
                          </span>
                          {!hasUnifiedData && (
                            <span className="rounded-md bg-amber-50 px-3 py-1 text-xs font-semibold text-amber-700 border border-amber-200">
                              Limited data
                            </span>
                          )}
                        </div>
                      </div>
                    </section>

                    <div className="grid grid-cols-1 md:grid-cols-2 xl:grid-cols-4 gap-4">
                      <div className="rounded-xl border border-red-200 bg-gradient-to-br from-red-50 to-white p-4">
                        <p className="text-xs font-semibold tracking-wide text-red-800 uppercase">Exposure</p>
                        <p className="text-4xl font-bold text-red-700 mt-1">
                          {hasUnifiedData ? clampScore(unifiedReport.exposure_score).toFixed(1) : "N/A"}
                        </p>
                        <div className="mt-3 h-2 w-full rounded-full bg-red-100 overflow-hidden">
                          <div
                            className="h-full bg-red-500 transition-all"
                            style={{ width: hasUnifiedData ? `${clampScore(unifiedReport.exposure_score)}%` : "0%" }}
                          />
                        </div>
                        {hasUnifiedData && unifiedReport.exposure_reasoning ? (
                          <p className="mt-3 text-xs text-red-800">{unifiedReport.exposure_reasoning.summary}</p>
                        ) : (
                          <p className="mt-3 text-xs text-red-800">No exposure data was returned by the connected providers.</p>
                        )}
                      </div>

                      <div className="rounded-xl border border-orange-200 bg-gradient-to-br from-orange-50 to-white p-4">
                        <p className="text-xs font-semibold tracking-wide text-orange-800 uppercase">Threat</p>
                        <p className="text-4xl font-bold text-orange-700 mt-1">
                          {hasUnifiedData ? clampScore(unifiedReport.threat_score).toFixed(1) : "N/A"}
                        </p>
                        <div className="mt-3 h-2 w-full rounded-full bg-orange-100 overflow-hidden">
                          <div
                            className="h-full bg-orange-500 transition-all"
                            style={{ width: hasUnifiedData ? `${clampScore(unifiedReport.threat_score)}%` : "0%" }}
                          />
                        </div>
                        {hasUnifiedData && unifiedReport.threat_reasoning ? (
                          <p className="mt-3 text-xs text-orange-800">{unifiedReport.threat_reasoning.summary}</p>
                        ) : (
                          <p className="mt-3 text-xs text-orange-800">No threat telemetry was returned for this IOC.</p>
                        )}
                      </div>

                      <div className="rounded-xl border border-green-200 bg-gradient-to-br from-green-50 to-white p-4">
                        <p className="text-xs font-semibold tracking-wide text-green-800 uppercase">Confidence</p>
                        <p className="text-4xl font-bold text-green-700 mt-1">
                          {hasUnifiedData ? `${clampScore(unifiedReport.confidence_score * 100).toFixed(0)}%` : "N/A"}
                        </p>
                        <div className="mt-3 h-2 w-full rounded-full bg-green-100 overflow-hidden">
                          <div
                            className="h-full bg-green-500 transition-all"
                            style={{ width: hasUnifiedData ? `${clampScore(unifiedReport.confidence_score * 100)}%` : "0%" }}
                          />
                        </div>
                        {hasUnifiedData && unifiedReport.confidence_reasoning ? (
                          <p className="mt-3 text-xs text-green-800">{unifiedReport.confidence_reasoning}</p>
                        ) : (
                          <p className="mt-3 text-xs text-green-800">Limited provider coverage. Confidence is unavailable until at least one source responds.</p>
                        )}
                      </div>

                      <div className="rounded-xl border border-blue-200 bg-gradient-to-br from-blue-50 to-white p-4">
                        <p className="text-xs font-semibold tracking-wide text-blue-800 uppercase">Sources</p>
                        <p className="text-4xl font-bold text-blue-700 mt-1">{unifiedReport.sources_queried.length}</p>
                        <p className="mt-3 text-xs text-blue-800">
                          {unifiedReport.sources_queried.length > 0 ? `${unifiedReport.sources_queried.length} provider(s) responded` : "No successful source responses"}
                        </p>
                      </div>
                    </div>

                    <section className="grid grid-cols-1 xl:grid-cols-3 gap-4">
                      <article className="xl:col-span-2 rounded-xl border border-slate-200 bg-white p-4">
                        <h5 className="text-sm font-semibold uppercase tracking-wide text-slate-700 mb-3">Findings</h5>
                        {unifiedReport.findings.length > 0 ? (
                          <div className="space-y-3 max-h-72 overflow-auto pr-1">
                            {unifiedReport.findings.map((finding, idx) => (
                              <div key={idx} className="rounded-lg border border-slate-200 bg-slate-50 p-3">
                                <div className="flex items-start justify-between gap-2">
                                  <div className="min-w-0">
                                    <p className="text-sm font-semibold text-slate-900">{finding.title}</p>
                                    <p className="text-xs text-slate-600 mt-1">{finding.description}</p>
                                    <p className="text-xs text-slate-500 mt-2">Source: External</p>
                                  </div>
                                  <span className={riskBadgeClass(finding.severity)}>{finding.severity}</span>
                                </div>
                              </div>
                            ))}
                          </div>
                        ) : (
                          <p className="text-sm text-slate-600">
                            No direct threat findings were returned for this IOC. This usually means benign or limited provider data.
                          </p>
                        )}
                      </article>

                      <article className="rounded-xl border border-slate-200 bg-white p-4">
                        <h5 className="text-sm font-semibold uppercase tracking-wide text-slate-700 mb-3">Investigation Brief</h5>
                        <div className="space-y-3 text-sm text-slate-700">
                          <p><span className="font-semibold text-slate-900">Risk:</span> {unifiedReport.risk_level}</p>
                          <p><span className="font-semibold text-slate-900">Reputation:</span> {unifiedReport.reputation_status}</p>
                          <p><span className="font-semibold text-slate-900">Updated:</span> {new Date(unifiedReport.last_updated).toLocaleString()}</p>
                          <p><span className="font-semibold text-slate-900">Sources Queried:</span> {unifiedReport.sources_queried.length}</p>
                          {unifiedReport.sources_failed.length > 0 && (
                            <p><span className="font-semibold text-slate-900">Failed Sources (count):</span> {unifiedReport.sources_failed.length}</p>
                          )}
                          {unifiedReport.findings_summary && (
                            <p className="rounded-md bg-slate-50 border border-slate-200 p-2 text-xs leading-5 text-slate-600">
                              {unifiedReport.findings_summary}
                            </p>
                          )}
                        </div>
                      </article>
                    </section>

                    <div className="flex gap-3 pt-2">
                      <button
                        onClick={handleExportPDF}
                        disabled={exportingPDF || exportingCSV}
                        className="flex-1 btn btn-primary"
                      >
                        <Download size={16} />
                        {exportingPDF ? "Exporting..." : "Export PDF"}
                      </button>
                      <button
                        onClick={handleExportCSV}
                        disabled={exportingCSV || exportingPDF}
                        className="flex-1 btn btn-success"
                      >
                        <FileText size={16} />
                        {exportingCSV ? "Exporting..." : "Export CSV"}
                      </button>
                    </div>
                  </div>
                )}

                {!unifiedReport && !loading && (
                  <p className="text-center text-gray-500 py-8">Enter a search query to begin investigation</p>
                )}
              </article>
            </div>
          )}

          {sessionReady && view === "alerts" && (
            <article className="chart-container">
              <h3 className="panel-title mb-4">Live Alerts</h3>
              <div className="space-y-3 max-h-[35rem] overflow-auto pr-2">
                {alerts.map((alert) => (
                  <div key={alert.id} className="rounded-lg border border-gray-200 bg-white p-3 hover:shadow-md transition">
                    {(() => {
                      const band = getRiskBand(alert.risk_score);
                      return (
                        <>
                          <div className="flex items-start justify-between gap-3">
                            <div>
                              <p className="font-semibold text-gray-900">{alert.query}</p>
                              <p className="text-sm text-gray-600 mt-1">{alert.reason}</p>
                            </div>
                            <span className={`risk-badge ${band.tone}`}>{band.label}</span>
                          </div>
                          <div className="mt-3 flex items-center justify-between">
                            <span className="text-sm text-gray-600">Score {alert.risk_score.toFixed(1)}</span>
                            {alert.status === "open" ? (
                              <button className="text-sm text-blue-600 hover:underline" onClick={() => ackAlert(alert.id)}>
                                Acknowledge
                              </button>
                            ) : (
                              <span className="text-xs text-gray-500">Acknowledged</span>
                            )}
                          </div>
                        </>
                      );
                    })()}
                  </div>
                ))}
                {alerts.length === 0 && (
                  <p className="text-sm text-gray-500 py-4">No active alerts</p>
                )}
              </div>
            </article>
          )}

          {sessionReady && view === "admin" && (
            <article className="chart-container">
              <h3 className="panel-title mb-4">Administration</h3>
              <div className="space-y-4">
                <div className="rounded-lg bg-blue-50 border border-blue-200 p-4">
                  <h4 className="font-semibold text-blue-900 mb-2">System Status</h4>
                  <p className="text-sm text-blue-700">All services operational</p>
                </div>
                <div className="rounded-lg bg-gray-50 border border-gray-200 p-4">
                  <h4 className="font-semibold text-gray-900 mb-2">Database</h4>
                  <p className="text-sm text-gray-700">Connected - Latest backup 2 hours ago</p>
                </div>
              </div>
            </article>
          )}
        </div>
      </div>
    </>
  );
}
