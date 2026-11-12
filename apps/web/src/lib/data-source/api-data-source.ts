/**
 * @file api-data-source.ts
 * @brief `AveroDataSource` implementation backed by the local `avero serve` API.
 * @details Implements M2–M4 surfaces from docs/api/openapi.yaml: reports, paged
 *          strings, evidence, hex, scan jobs + SSE progress, disassembly, decompile,
 *          engines, APK manifest/dotnet facts and report diffs.
 */

import type { AveroReport, Evidence, ReportSummary, StringEntry } from "@/types/report";
import type {
  ApiHealth,
  DecompileRequest,
  DecompileResult,
  DiffResult,
  DisassemblyPage,
  DisassemblyQuery,
  EngineInfo,
  JobEvent,
  JobSnapshot,
  ScanOptions,
} from "@/types/api";
import type { AveroDataSource, HexSlice, Page, StringQuery } from "./types";

interface ErrorEnvelope {
  error?: { code?: string; message?: string; details?: unknown };
}

/**
 * @class ApiDataSource
 * @brief Client for the loopback-only Avero REST/SSE API.
 */
export class ApiDataSource implements AveroDataSource {
  private readonly baseUrl: string;

  /**
   * @param baseUrl API base URL, e.g. `http://127.0.0.1:8787`.
   */
  constructor(baseUrl: string) {
    this.baseUrl = baseUrl.replace(/\/+$/, "");
  }

  private async request<T>(path: string, init?: RequestInit): Promise<T> {
    const response = await fetch(`${this.baseUrl}${path}`, {
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
      let message = `API request failed (${response.status} ${response.statusText})`;
      try {
        const payload = (await response.json()) as ErrorEnvelope;
        if (payload?.error?.message) {
          message = `${payload.error.code ? `${payload.error.code}: ` : ""}${payload.error.message}`;
        }
      } catch {
        // Non-JSON error body; keep the status message.
      }
      throw new Error(message);
    }
    return (await response.json()) as T;
  }

  /** @brief API/engine health used by the status bar and settings page. */
  public async health(): Promise<ApiHealth> {
    return this.request<ApiHealth>("/api/health");
  }

  /** @brief The API exposes no report listing endpoint; returns an empty list. */
  public async listReports(): Promise<ReportSummary[]> {
    return [];
  }

  /** @brief Fetches a full `avero.report/v1` document by artifact SHA-256. */
  public async getReport(reportId: string): Promise<AveroReport> {
    return this.request<AveroReport>(`/api/reports/${encodeURIComponent(reportId)}`);
  }

  /** @brief Fetches a single evidence record by ID. */
  public async getEvidence(reportId: string, evidenceId: string): Promise<Evidence | null> {
    try {
      return await this.request<Evidence>(
        `/api/reports/${encodeURIComponent(reportId)}/evidence/${encodeURIComponent(evidenceId)}`,
      );
    } catch {
      return null;
    }
  }

  /** @brief Paged string search via `/api/reports/{id}/strings`. */
  public async getStrings(reportId: string, query?: StringQuery): Promise<Page<StringEntry>> {
    const parameters = new URLSearchParams();
    if (query?.q) parameters.set("q", query.q);
    if (query?.encoding) parameters.set("encoding", query.encoding);
    if (query?.offset !== undefined) parameters.set("offset", String(query.offset));
    if (query?.limit !== undefined) parameters.set("limit", String(query.limit));
    const suffix = parameters.toString() ? `?${parameters.toString()}` : "";
    const page = await this.request<{
      items: StringEntry[];
      total: number | null;
      next_cursor: string | null;
    }>(`/api/reports/${encodeURIComponent(reportId)}/strings${suffix}`);
    return {
      items: page.items,
      total: page.total ?? page.items.length,
      offset: query?.offset ?? 0,
      limit: query?.limit,
    };
  }

  /** @brief Reads a hex slice (base64-decoded) from the stored artifact bytes. */
  public async getHex(
    reportId: string,
    offset: number,
    length: number,
  ): Promise<HexSlice | null> {
    try {
      const slice = await this.request<{
        offset: number;
        length: number;
        bytes_base64: string;
      }>(
        `/api/reports/${encodeURIComponent(reportId)}/hex?offset=${offset}&length=${Math.min(
          Math.max(1, length),
          65536,
        )}`,
      );
      const bytes = Uint8Array.from(atob(slice.bytes_base64), (character) =>
        character.charCodeAt(0),
      );
      return {
        offset: slice.offset,
        length: slice.length,
        totalSize: slice.offset + bytes.length,
        bytes,
      };
    } catch {
      return null;
    }
  }

  /** @brief API mode does not ingest local report JSON; use {@link scan}. */
  public async loadReport(): Promise<AveroReport> {
    throw new Error("API mode does not load report files; scan an artifact instead");
  }

  /** @brief Uploads an artifact to `/api/scans` and returns the scan job. */
  public async scan(file: File, options?: ScanOptions): Promise<{ job_id: string }> {
    const form = new FormData();
    form.append("file", file, file.name);
    if (options) {
      const compact = Object.fromEntries(
        Object.entries(options).filter(([, value]) => value !== undefined && value !== ""),
      );
      if (Object.keys(compact).length > 0) {
        form.append("options", JSON.stringify(compact));
      }
    }
    return this.request<{ job_id: string; status: string }>("/api/scans", {
      method: "POST",
      body: form,
    });
  }

  /** @brief Polls one job snapshot. */
  public async getJob(jobId: string): Promise<JobSnapshot> {
    return this.request<JobSnapshot>(`/api/jobs/${encodeURIComponent(jobId)}`);
  }

  /**
   * @brief Subscribes to job progress over Server-Sent Events.
   * @return Unsubscribe callback that closes the EventSource.
   */
  public subscribeJob(jobId: string, onEvent: (event: JobEvent) => void): () => void {
    if (typeof window === "undefined" || typeof EventSource === "undefined") {
      return () => undefined;
    }
    const source = new EventSource(
      `${this.baseUrl}/api/jobs/${encodeURIComponent(jobId)}/events`,
    );
    source.onmessage = (message) => {
      try {
        const event = JSON.parse(message.data) as JobEvent;
        onEvent(event);
        if (event.type === "done" || event.type === "error") {
          source.close();
        }
      } catch {
        // Ignore malformed SSE frames.
      }
    };
    source.onerror = () => {
      source.close();
    };
    return () => source.close();
  }

  /** @brief Rizin-backed disassembly page. */
  public async getDisassembly(
    reportId: string,
    query?: DisassemblyQuery,
  ): Promise<DisassemblyPage> {
    const parameters = new URLSearchParams();
    if (query?.start) parameters.set("start", query.start);
    if (query?.limit !== undefined) parameters.set("limit", String(query.limit));
    if (query?.analyze) parameters.set("analyze", "true");
    const suffix = parameters.toString() ? `?${parameters.toString()}` : "";
    return this.request<DisassemblyPage>(
      `/api/reports/${encodeURIComponent(reportId)}/disassembly${suffix}`,
    );
  }

  /** @brief Starts a decompile job (ilspycmd for .NET, ghidra for native). */
  public async decompile(
    reportId: string,
    request: DecompileRequest,
  ): Promise<{ job_id: string }> {
    return this.request<{ job_id: string; status: string }>(
      `/api/reports/${encodeURIComponent(reportId)}/decompile`,
      { method: "POST", body: JSON.stringify(request) },
    );
  }

  /** @brief Lists engine packs and install state. */
  public async getEngines(): Promise<EngineInfo[]> {
    const response = await this.request<{ items: EngineInfo[] }>("/api/engines");
    return response.items;
  }

  /** @brief Starts an engine install job. */
  public async installEngine(engineId: string): Promise<{ job_id: string }> {
    return this.request<{ job_id: string; status: string }>(
      `/api/engines/${encodeURIComponent(engineId)}/install`,
      { method: "POST" },
    );
  }

  /** @brief Parsed APK manifest facts (signers/resources/components). */
  public async getApkManifest(reportId: string): Promise<Record<string, unknown>> {
    return this.request<Record<string, unknown>>(
      `/api/reports/${encodeURIComponent(reportId)}/apk-manifest`,
    );
  }

  /** @brief .NET metadata facts. */
  public async getDotnet(reportId: string): Promise<Record<string, unknown>> {
    return this.request<Record<string, unknown>>(
      `/api/reports/${encodeURIComponent(reportId)}/dotnet`,
    );
  }

  /** @brief Compares two stored reports (`avero.diff/v1`). */
  public async diff(oldReport: string, newReport: string): Promise<DiffResult> {
    return this.request<DiffResult>("/api/diffs", {
      method: "POST",
      body: JSON.stringify({ old_report: oldReport, new_report: newReport }),
    });
  }

  /** @brief Retrieves a decompile job's result files from its job snapshot. */
  public async getDecompileResult(jobId: string): Promise<DecompileResult | null> {
    const job = await this.getJob(jobId);
    const result = job.result as DecompileResult | undefined;
    return result && Array.isArray(result.files) ? result : null;
  }
}
