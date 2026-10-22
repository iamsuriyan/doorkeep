// Thin client for /admin/v1. Holds the CSRF token returned at login (or by
// /me after a reload) and sends it on every write.
let csrf = "";

export class ApiError extends Error {
  constructor(public status: number, message: string) {
    super(message);
  }
}

export async function api<T = any>(method: string, path: string, body?: unknown): Promise<T> {
  // Relative to the dashboard page (always served at .../admin/), so the
  // dashboard also works when a proxy mounts it under a path prefix.
  const res = await fetch("v1" + path, {
    method,
    credentials: "same-origin",
    headers: { "Content-Type": "application/json", ...(csrf && method !== "GET" ? { "X-CSRF-Token": csrf } : {}) },
    body: body === undefined ? undefined : JSON.stringify(body),
  });
  if (res.status === 204) return undefined as T;
  const data = await res.json().catch(() => ({}));
  if (!res.ok) throw new ApiError(res.status, data.detail || res.statusText);
  return data as T;
}

export async function login(user: string, password: string): Promise<void> {
  const r = await api<{ csrf: string }>("POST", "/login", { user, password });
  csrf = r.csrf;
}

export async function me(): Promise<string | null> {
  try {
    const r = await api<{ actor: string; csrf?: string }>("GET", "/me");
    if (r.csrf) csrf = r.csrf;
    return r.actor;
  } catch {
    return null;
  }
}

export async function logout(): Promise<void> {
  await api("POST", "/logout").catch(() => {});
  csrf = "";
}

// ---- types mirrored from the Go API ----

export type Outcome = "allow" | "challenge" | "block";

export interface Thresholds { t_challenge: number; t_block: number }

export interface Site {
  id: string;
  name: string;
  site_key: string;
  origins: string[];
  thresholds: Thresholds;
  mode: "enforce" | "monitor" | "challenge_only";
  interactive_actions: string[] | null;
  strict_ip: boolean;
  accessibility_url?: string;
  created_at: string;
}

export interface Reason { code: string; w: number }

export interface Event {
  id: string;
  ts: string;
  action: string;
  risk: number;
  outcome: Outcome;
  would_be: Outcome;
  reasons: Reason[] | null;
  shadow: Reason[] | null;
  fp: string;
  asn: number;
  asn_class: string;
  country: string;
  ua_family: string;
  ua_major: number;
  os_family: string;
  challenge_kind: string;
  challenge_ok?: boolean;
  verified_at?: string;
  label?: string;
  feature_groups?: Record<string, Array<{ key: string; value: number | string; desc: string }>>;
}

export interface Stats {
  range: string;
  series: Array<{ hour: string; allow: number; challenge: number; block: number }>;
  totals: Record<string, number>;
  total: number;
  verified: number;
  reasons: Array<{ key: string; count: number }>;
  countries: Array<{ key: string; count: number }>;
  browsers: Array<{ key: string; count: number }>;
  asn_class: Array<{ key: string; count: number }>;
  risk_hist: number[];
  challenge: Record<string, number>;
  labels: Record<string, number>;
}

export interface Rule {
  id: string;
  when: string;
  unless?: string;
  weight: number;
  mode: "enforce" | "shadow" | "off";
  floor?: boolean;
  informational?: boolean;
  description?: string;
  builtin: boolean;
  overridden: boolean;
}

export interface ListEntry { id: number; kind: string; value: string; action: string; note: string; expires_at?: string }

export interface ModelStatus {
  hbos_observations: number;
  hbos_active: boolean;
  supervised: { labels: number; bots: number; humans: number; precision: number; recall: number; ready: boolean; promoted: boolean };
}

export interface LabResult {
  rule: string;
  days: number;
  events: number;
  fired: number;
  changed: number;
  transitions: Record<string, number>;
  labelled: { bots_fired: number; bots_total: number; humans_fired: number; humans_total: number };
  samples: string[];
}

export const fmt = (n: number) => n.toLocaleString("en");
export const pct = (a: number, b: number) => (b ? Math.round((a / b) * 1000) / 10 : 0) + "%";
