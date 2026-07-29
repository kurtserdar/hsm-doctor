import type {
  BenchResult,
  CertsResponse,
  DiscoverResponse,
  DriftEvent,
  HSMSummary,
  ScanReport,
  ScanSummary,
  ServerInfo,
  TestResult,
} from "./types";

// ApiError carries the HTTP status so callers can react to 401 separately.
export class ApiError extends Error {
  status: number;
  constructor(message: string, status: number) {
    super(message);
    this.status = status;
  }
}

const TOKEN_KEY = "hsmdoctor_token";
let authToken = localStorage.getItem(TOKEN_KEY) ?? "";

export function setAuthToken(token: string): void {
  authToken = token;
  localStorage.setItem(TOKEN_KEY, token);
}

async function request<T>(path: string, init?: RequestInit): Promise<T> {
  const headers = new Headers(init?.headers);
  if (authToken) {
    headers.set("Authorization", `Bearer ${authToken}`);
  }
  const resp = await fetch(path, { ...init, headers });
  const body = await resp.json().catch(() => null);
  if (!resp.ok) {
    const message =
      body && typeof body.error === "string"
        ? body.error
        : `${resp.status} ${resp.statusText}`;
    throw new ApiError(message, resp.status);
  }
  return body as T;
}

export function serverInfo(): Promise<ServerInfo> {
  return request("/api/v1/info");
}

export function fleet(): Promise<HSMSummary[]> {
  return request("/api/v1/hsms");
}

export function hsmScans(id: number, limit = 50): Promise<ScanSummary[]> {
  return request(`/api/v1/hsms/${id}/scans?limit=${limit}`);
}

export function hsmScan(id: number, scanID: number): Promise<ScanSummary> {
  return request(`/api/v1/hsms/${id}/scans/${scanID}`);
}

export function hsmDrift(id: number, limit = 20): Promise<DriftEvent[]> {
  return request(`/api/v1/hsms/${id}/drift?limit=${limit}`);
}

export function discover(withMechanisms = false): Promise<DiscoverResponse> {
  const qs = withMechanisms ? "?mechanisms=true" : "";
  return request(`/api/v1/discover${qs}`);
}

export function scan(slot: number): Promise<ScanReport> {
  return request(`/api/v1/slots/${slot}/scan`);
}

export function certs(slot: number, warnDays: number): Promise<CertsResponse> {
  return request(`/api/v1/slots/${slot}/certs?warn_days=${warnDays}`);
}

export function runTest(slot: number, profile: string): Promise<TestResult> {
  return request(`/api/v1/slots/${slot}/test`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ profile }),
  });
}

export function runBench(
  slot: number,
  opts: { duration_ms: number; max_ops: number; sessions: number },
): Promise<BenchResult> {
  return request(`/api/v1/slots/${slot}/bench`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(opts),
  });
}
