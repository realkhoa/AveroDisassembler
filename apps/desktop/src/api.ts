/** Local `avero serve` API client (`avero.api/v1`) for the desktop workbench. */

import type {
  DiffResult,
  EngineInfo,
  Health,
  Job,
  JobEvent,
  Report,
  StringEntry,
} from "./types";

export const DEFAULT_API_URL = "http://127.0.0.1:8787";
export const API_URL_KEY = "avero_api_url";

export function getApiUrl(): string {
  return localStorage.getItem(API_URL_KEY) || DEFAULT_API_URL;
}

export function setApiUrl(url: string): void {
  localStorage.setItem(API_URL_KEY, url.replace(/\/+$/, "") || DEFAULT_API_URL);
}

async function request<T>(base: string, path: string, init?: RequestInit): Promise<T> {
  const response = await fetch(`${base.replace(/\/+$/, "")}${path}`, {
    ...init,
    headers: {
      Accept: "application/json",
      ...(init?.body && !(init.body instanceof FormData)
        ? { "Content-Type": "application/json" }
        : {}),
      ...(init?.headers || {}),
    },
  });
  if (!response.ok) {
    let message = `API ${response.status} ${response.statusText}`;
    try {
      const payload = (await response.json()) as { error?: { code?: string; message?: string } };
      if (payload.error?.message) {
        message = `${payload.error.code ? `${payload.error.code}: ` : ""}${payload.error.message}`;
      }
    } catch {
      /* keep status message */
    }
    throw new Error(message);
  }
  return (await response.json()) as T;
}

export function health(base = getApiUrl()): Promise<Health> {
  return request<Health>(base, "/api/health");
}

export function getReport(base: string, id: string): Promise<Report> {
  return request<Report>(base, `/api/reports/${id}`);
}

export function scan(
  base: string,
  file: File,
  options?: { min_string_len?: number; max_strings?: number; only?: string; skip?: string },
): Promise<{ job_id: string }> {
  const form = new FormData();
  form.append("file", file, file.name);
  const compact = Object.fromEntries(
    Object.entries(options || {}).filter(([, value]) => value !== undefined && value !== ""),
  );
  if (Object.keys(compact).length > 0) form.append("options", JSON.stringify(compact));
  return request<{ job_id: string }>(base, "/api/scans", { method: "POST", body: form });
}

export function getJob(base: string, id: string): Promise<Job> {
  return request<Job>(base, `/api/jobs/${id}`);
}

export function subscribeJob(
  base: string,
  id: string,
  onEvent: (event: JobEvent) => void,
): () => void {
  const source = new EventSource(`${base.replace(/\/+$/, "")}/api/jobs/${id}/events`);
  source.onmessage = (message) => {
    try {
      const event = JSON.parse(message.data) as JobEvent;
      onEvent(event);
      if (event.type === "done" || event.type === "error") source.close();
    } catch {
      /* ignore malformed frame */
    }
  };
  source.onerror = () => source.close();
  return () => source.close();
}

export function getStrings(
  base: string,
  reportId: string,
  query: { q?: string; limit?: number; offset?: number; encoding?: string },
): Promise<{ items: StringEntry[]; total: number | null }> {
  const params = new URLSearchParams();
  if (query.q) params.set("q", query.q);
  if (query.limit !== undefined) params.set("limit", String(query.limit));
  if (query.offset !== undefined) params.set("offset", String(query.offset));
  if (query.encoding) params.set("encoding", query.encoding);
  return request(base, `/api/reports/${reportId}/strings?${params.toString()}`);
}

export async function getHex(
  base: string,
  reportId: string,
  offset: number,
  length: number,
): Promise<Uint8Array> {
  const slice = await request<{ bytes_base64: string }>(
    base,
    `/api/reports/${reportId}/hex?offset=${offset}&length=${length}`,
  );
  return Uint8Array.from(atob(slice.bytes_base64), (character) => character.charCodeAt(0));
}

export function getDisassembly(
  base: string,
  reportId: string,
  query: { start?: string; limit?: number; analyze?: boolean },
): Promise<{ address: string; items: import("./types").Instruction[] }> {
  const params = new URLSearchParams();
  if (query.start) params.set("start", query.start);
  if (query.limit !== undefined) params.set("limit", String(query.limit));
  if (query.analyze) params.set("analyze", "true");
  return request(base, `/api/reports/${reportId}/disassembly?${params.toString()}`);
}

export function decompile(
  base: string,
  reportId: string,
  body: { engine: "ilspycmd" | "ghidra"; type?: string; limit?: number },
): Promise<{ job_id: string }> {
  return request(base, `/api/reports/${reportId}/decompile`, {
    method: "POST",
    body: JSON.stringify(body),
  });
}

export async function getEngines(base: string): Promise<EngineInfo[]> {
  const response = await request<{ items: EngineInfo[] }>(base, "/api/engines");
  return response.items;
}

export function installEngine(base: string, id: string): Promise<{ job_id: string }> {
  return request(base, `/api/engines/${id}/install`, { method: "POST" });
}

export function diff(base: string, oldReport: string, newReport: string): Promise<DiffResult> {
  return request(base, "/api/diffs", {
    method: "POST",
    body: JSON.stringify({ old_report: oldReport, new_report: newReport }),
  });
}

export function apkManifest(base: string, reportId: string): Promise<Record<string, unknown>> {
  return request(base, `/api/reports/${reportId}/apk-manifest`);
}

export function dotnet(base: string, reportId: string): Promise<Record<string, unknown>> {
  return request(base, `/api/reports/${reportId}/dotnet`);
}
