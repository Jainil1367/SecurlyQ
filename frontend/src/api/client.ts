import type {
  Alert,
  AlertDetail,
  AlertFilters,
  AlertPage,
  AlertStatus,
  AlertSummary,
  AnalysisResult,
  Explanation,
  Note,
  User,
} from "./types";

const BASE = (import.meta.env.VITE_API_BASE_URL ?? "") + "/api/v1";

/** One error type for every failed request, so UI code handles a single case. */
export class ApiError extends Error {
  constructor(
    public status: number,
    message: string,
  ) {
    super(message);
    this.name = "ApiError";
  }
}

type TokenGetter = () => string | null;
type UnauthorizedHandler = () => void;

let getToken: TokenGetter = () => null;
let onUnauthorized: UnauthorizedHandler = () => {};

/** The auth layer plugs itself in here, so this file never imports React. */
export function configureClient(opts: { getToken: TokenGetter; onUnauthorized: UnauthorizedHandler }): void {
  getToken = opts.getToken;
  onUnauthorized = opts.onUnauthorized;
}

function messageFrom(body: unknown, fallback: string): string {
  if (body && typeof body === "object" && "detail" in body) {
    const detail = (body as { detail: unknown }).detail;
    if (typeof detail === "string") return detail;
    if (Array.isArray(detail) && detail.length > 0) {
      const first = detail[0] as { msg?: string };
      if (first?.msg) return first.msg;
    }
  }
  return fallback;
}

async function request<T>(path: string, init: RequestInit = {}, opts: { auth?: boolean } = {}): Promise<T> {
  const headers = new Headers(init.headers);
  const token = getToken();
  if (opts.auth !== false && token) headers.set("Authorization", `Bearer ${token}`);
  if (init.body && !(init.body instanceof URLSearchParams) && !headers.has("Content-Type")) {
    headers.set("Content-Type", "application/json");
  }

  let response: Response;
  try {
    response = await fetch(BASE + path, { ...init, headers });
  } catch {
    throw new ApiError(0, "Cannot reach the SecurlyQ API. Check your connection and try again.");
  }

  const body: unknown = await response.json().catch(() => null);
  if (!response.ok) {
    if (response.status === 401 && opts.auth !== false) onUnauthorized();
    throw new ApiError(response.status, messageFrom(body, `Request failed (${response.status})`));
  }
  return body as T;
}

export async function login(email: string, password: string): Promise<string> {
  // The login route follows the OAuth2 password form: form-encoded, field name "username".
  const form = new URLSearchParams({ username: email, password });
  const out = await request<{ access_token: string }>("/auth/login", { method: "POST", body: form }, { auth: false });
  return out.access_token;
}

export const getMe = () => request<User>("/auth/me");

export function listAlerts(filters: AlertFilters = {}): Promise<AlertPage> {
  const params = new URLSearchParams();
  for (const [key, value] of Object.entries(filters)) {
    if (value !== undefined && value !== "") params.set(key, String(value));
  }
  const qs = params.toString();
  return request<AlertPage>(`/alerts${qs ? `?${qs}` : ""}`);
}

export const getSummary = () => request<AlertSummary>("/alerts/summary");
export const getAlert = (id: number) => request<AlertDetail>(`/alerts/${id}`);

export const updateStatus = (id: number, status: AlertStatus) =>
  request<Alert>(`/alerts/${id}`, { method: "PATCH", body: JSON.stringify({ status }) });

export const addNote = (id: number, notes: string) =>
  request<Note>(`/alerts/${id}/notes`, { method: "POST", body: JSON.stringify({ notes }) });

export const explainAlert = (id: number, refresh = false) =>
  request<Explanation>(`/alerts/${id}/explain${refresh ? "?refresh=true" : ""}`, { method: "POST" });

export const runAnalysis = () => request<AnalysisResult>("/analysis/run", { method: "POST", body: "{}" });
