/**
 * @file types.ts
 * @brief Common types and interfaces for Avero data sources.
 * @details Implements the contract interface defined in UI-SPEC Section 4.2.
 */

import type { AveroReport, Evidence, Finding, ReportSummary, StringEntry } from "@/types/report";
import type {
  ApiHealth,
  DecompileRequest,
  DiffResult,
  DisassemblyPage,
  DisassemblyQuery,
  EngineInfo,
  FindingQuery,
  JobEvent,
  JobSnapshot,
  ScanOptions,
} from "@/types/api";

/**
 * @brief Query parameters for filtering strings.
 */
export interface StringQuery {
  q?: string;
  encoding?: string;
  offset?: number;
  limit?: number;
}

/**
 * @brief Generic paginated response wrapper.
 */
export interface Page<T> {
  items: T[];
  total: number;
  offset?: number;
  limit?: number;
}

/**
 * @brief Sliced raw byte window for hex inspection.
 */
export interface HexSlice {
  offset: number;
  length: number;
  totalSize: number;
  bytes: Uint8Array;
}

/**
 * @brief Core contract abstraction decoupling UI screens from backend delivery mode.
 */
export interface AveroDataSource {
  /**
   * @brief Lists summarized reports stored in local cache or returned by API.
   * @return Array of report summaries.
   */
  listReports?(): Promise<ReportSummary[]>;

  /**
   * @brief Retrieves a full report by its unique ID.
   * @param reportId Unique report hash/identifier.
   * @return Fully parsed AveroReport object.
   */
  getReport(reportId: string): Promise<AveroReport>;

  /**
   * @brief Resolves a specific evidence item by its evidence identifier.
   * @param reportId Report identifier.
   * @param evidenceId Evidence identifier.
   * @return Resolved Evidence or null if missing.
   */
  getEvidence(reportId: string, evidenceId: string): Promise<Evidence | null>;

  /**
   * @brief Queries extracted strings with optional search query and encoding filters.
   * @param reportId Report identifier.
   * @param query Filtering and pagination query.
   * @return Paginated list of strings.
   */
  getStrings(reportId: string, query?: StringQuery): Promise<Page<StringEntry>>;

  /**
   * @brief Requests a byte slice for hex inspection.
   * @param reportId Report identifier.
   * @param offset Start byte offset.
   * @param length Number of bytes to read.
   * @return HexSlice containing bytes, or null if original artifact is not loaded.
   */
  getHex(reportId: string, offset: number, length: number): Promise<HexSlice | null>;

  /**
   * @brief Ingests a new report JSON string into memory/cache.
   * @param jsonContent Serialized avero.report/v1 JSON.
   * @param rawBytes Optional raw artifact binary data.
   * @return Parsed AveroReport.
   */
  loadReport(jsonContent: string, rawBytes?: Uint8Array): Promise<AveroReport>;

  // ---- API mode (M2–M4); FileDataSource leaves these undefined -----------------
  /** @brief Paged finding search (API mode only). */
  getFindings?(reportId: string, query?: FindingQuery): Promise<Page<Finding>>;

  /** @brief API/engine health (API mode only). */
  health?(): Promise<ApiHealth>;

  /** @brief Uploads an artifact and starts a scan job (API mode only). */
  scan?(file: File, options?: ScanOptions): Promise<{ job_id: string }>;

  /** @brief Polls a job snapshot (API mode only). */
  getJob?(jobId: string): Promise<JobSnapshot>;

  /** @brief Subscribes to SSE job progress; returns an unsubscribe callback. */
  subscribeJob?(jobId: string, onEvent: (event: JobEvent) => void): () => void;

  /** @brief Rizin-backed disassembly page (API mode only). */
  getDisassembly?(reportId: string, query?: DisassemblyQuery): Promise<DisassemblyPage>;

  /** @brief Starts a decompile job (API mode only). */
  decompile?(reportId: string, request: DecompileRequest): Promise<{ job_id: string }>;

  /** @brief Lists engine packs (API mode only). */
  getEngines?(): Promise<EngineInfo[]>;

  /** @brief Starts an engine install job (API mode only). */
  installEngine?(engineId: string): Promise<{ job_id: string }>;

  /** @brief Parsed APK manifest facts (API mode only). */
  getApkManifest?(reportId: string): Promise<Record<string, unknown>>;

  /** @brief .NET metadata facts (API mode only). */
  getDotnet?(reportId: string): Promise<Record<string, unknown>>;

  /** @brief Compares two stored reports (API mode only). */
  diff?(oldReport: string, newReport: string): Promise<DiffResult>;
}
