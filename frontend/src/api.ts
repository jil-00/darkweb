import axios from "axios";

export type SearchResponse = {
  query: string;
  query_type: string;
  total_findings: number;
  risk_score: number;
  findings: Array<{
    source: string;
    source_type: string;
    category: string;
    occurrences: number;
    sensitivity: number;
  }>;
  created_at: string;
};

export type ScoreExplanation = {
  summary: string;
  factors: string[];
  confidence: number;
};

export type Finding = {
  finding_type: string;
  title: string;
  description: string;
  severity: string;
  source: string;
  confidence: number;
};

export type UnifiedIntelligenceReport = {
  ioc_value: string;
  ioc_type: string;
  exposure_score: number;
  threat_score: number;
  reputation_status: string;
  confidence_score: number;
  risk_level: string;
  exposure_reasoning?: ScoreExplanation;
  threat_reasoning?: ScoreExplanation;
  reputation_reasoning?: string;
  confidence_reasoning?: string;
  findings: Finding[];
  findings_summary: string;
  virustotal?: any;
  shodan?: any;
  ipinfo?: any;
  sources_queried: string[];
  sources_failed: string[];
  investigation_timestamp: string;
  last_updated: string;
  analyst_notes?: string;
};

const API_BASE = import.meta.env.VITE_API_URL ?? "http://localhost:8000/api/v1";

const api = axios.create({
  baseURL: API_BASE
});

function getStoredToken(): string | null {
  return localStorage.getItem("token") || localStorage.getItem("access_token");
}

api.interceptors.request.use((config) => {
  const token = getStoredToken();
  if (token) {
    // Keep one canonical key so the rest of the app can rely on it.
    localStorage.setItem("token", token);
    config.headers.Authorization = `Bearer ${token}`;
  }
  return config;
});

export async function login(email: string, password: string) {
  const { data } = await api.post("/auth/login", { email, password });
  return data as { access_token: string };
}

export async function register(email: string, password: string) {
  const { data } = await api.post("/auth/register", { email, password });
  return data as { access_token: string };
}

export async function fetchDashboard() {
  const { data } = await api.get("/dashboard/overview");
  return data;
}

export async function searchIntel(payload: {
  query: string;
  query_type: "email" | "domain" | "username";
  use_regex: boolean;
  fuzzy: boolean;
}) {
  const { data } = await api.post("/intel/search", payload);
  return data as SearchResponse;
}

export async function scan(payload: {
  query: string;
  query_type: "email" | "domain" | "username";
  use_regex: boolean;
  fuzzy: boolean;
}) {
  const { data } = await api.post("/scan", payload);
  return data as SearchResponse;
}

export async function getResults(query: string) {
  const { data } = await api.get(`/results/${encodeURIComponent(query)}`);
  return data as SearchResponse;
}

export async function listAlerts() {
  const { data } = await api.get("/alerts");
  return data as Array<{
    id: string;
    query: string;
    risk_score: number;
    reason: string;
    status: string;
    created_at: string;
  }>;
}

export async function acknowledgeAlert(alertId: string) {
  await api.patch(`/alerts/${alertId}/ack`);
}

export async function listWatchTargets() {
  const { data } = await api.get("/monitoring/watch");
  return data as Array<{
    id: string;
    target: string;
    query_type: string;
    interval_minutes: number;
    last_scanned_at: string | null;
  }>;
}

export async function addWatchTarget(payload: {
  target: string;
  query_type: "email" | "domain" | "username";
  interval_minutes: number;
}) {
  const { data } = await api.post("/monitoring/watch", payload);
  return data;
}

export async function triggerBackgroundScan() {
  const { data } = await api.post("/monitoring/trigger");
  return data as { message: string; task_id: string };
}

export async function unifiedEnrich(ioc_value: string) {
  const { data } = await api.post("/threat-intel/unified-enrich", {}, {
    params: { ioc_value }
  });
  return data as UnifiedIntelligenceReport;
}

export async function exportPDF(report: UnifiedIntelligenceReport, analyst_notes: string = ""): Promise<Blob> {
  const { data } = await api.post("/threat-intel/export/pdf", report, {
    params: { analyst_notes },
    responseType: "blob"
  });
  return data;
}

export async function exportCSV(report: UnifiedIntelligenceReport, analyst_notes: string = ""): Promise<Blob> {
  const { data } = await api.post("/threat-intel/export/csv", report, {
    params: { analyst_notes },
    responseType: "blob"
  });
  return data;
}

export function subscribeAlertStream(onMessage: (event: any) => void): EventSource | null {
  const streamUrl = `${API_BASE}/stream/alerts`;
  try {
    const source = new EventSource(streamUrl);
    source.onmessage = (event) => {
      try {
        onMessage(JSON.parse(event.data));
      } catch {
        onMessage({ event: "raw", payload: event.data });
      }
    };
    return source;
  } catch {
    return null;
  };
}
