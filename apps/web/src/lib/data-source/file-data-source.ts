/**
 * @file file-data-source.ts
 * @brief In-memory and local storage implementation of AveroDataSource for File Mode.
 * @details Handles offline inspection of user-dropped report.json files and artifact slices.
 */

import type { AveroReport, Evidence, ReportSummary, StringEntry } from "@/types/report";
import type { AveroDataSource, HexSlice, Page, StringQuery } from "./types";

/**
 * @class FileDataSource
 * @brief Concrete data source providing report data purely from client-side files.
 */
export class FileDataSource implements AveroDataSource {
  private reports: Map<string, AveroReport> = new Map();
  private artifactBytes: Map<string, Uint8Array> = new Map();
  private readonly STORAGE_KEY = "avero_recent_reports";

  /**
   * @brief Constructs a new FileDataSource instance.
   * @param initialReports Optional pre-loaded reports map.
   */
  constructor(initialReports?: AveroReport[]) {
    if (initialReports) {
      for (const r of initialReports) {
        this.reports.set(r.artifact.id, r);
      }
    }
  }

  /**
   * @brief Ingests and parses a report JSON string into memory.
   * @param jsonContent Serialized JSON content.
   * @param rawBytes Optional raw artifact binary bytes.
   * @return Fully parsed AveroReport.
   * @throws Error if JSON is invalid or missing required artifact metadata.
   */
  public async loadReport(jsonContent: string, rawBytes?: Uint8Array): Promise<AveroReport> {
    const parsed = JSON.parse(jsonContent) as AveroReport;

    if (!parsed || !parsed.artifact || !parsed.artifact.id) {
      throw new Error("Invalid Avero report: missing artifact.id");
    }

    const reportId = parsed.artifact.id;
    this.reports.set(reportId, parsed);

    if (rawBytes) {
      this.artifactBytes.set(reportId, rawBytes);
    }

    this.saveRecentSummary(parsed);
    return parsed;
  }

  /**
   * @brief Attaches raw binary bytes for an existing report to enable hex viewing.
   * @param reportId Report artifact ID.
   * @param bytes Uint8Array of the original artifact.
   */
  public setArtifactBytes(reportId: string, bytes: Uint8Array): void {
    this.artifactBytes.set(reportId, bytes);
  }

  /**
   * @brief Retrieves a report by its ID from memory.
   * @param reportId Artifact identifier.
   * @return AveroReport instance.
   * @throws Error if report is not found in memory.
   */
  public async getReport(reportId: string): Promise<AveroReport> {
    const report = this.reports.get(reportId);
    if (!report) {
      throw new Error(`Report not found in memory: ${reportId}`);
    }
    return report;
  }

  /**
   * @brief Resolves evidence by evidence ID for a given report.
   * @param reportId Artifact identifier.
   * @param evidenceId Evidence identifier.
   * @return Matching Evidence or null if absent.
   */
  public async getEvidence(reportId: string, evidenceId: string): Promise<Evidence | null> {
    const report = await this.getReport(reportId);
    const evidenceList = report.artifact.evidence || [];
    const match = evidenceList.find((e) => e.id === evidenceId);
    return match || null;
  }

  /**
   * @brief Queries extracted strings with text matching and encoding filters.
   * @param reportId Artifact identifier.
   * @param query Filtering and pagination parameters.
   * @return Paginated result containing matching StringEntry items.
   */
  public async getStrings(reportId: string, query?: StringQuery): Promise<Page<StringEntry>> {
    const report = await this.getReport(reportId);
    const allStrings = report.artifact.strings || [];

    let filtered = allStrings;

    if (query?.encoding) {
      const targetEnc = query.encoding.toLowerCase();
      filtered = filtered.filter((s) => s.encoding.toLowerCase() === targetEnc);
    }

    if (query?.q && query.q.trim().length > 0) {
      const qLower = query.q.toLowerCase();
      filtered = filtered.filter((s) => s.value.toLowerCase().includes(qLower));
    }

    const offset = query?.offset ?? 0;
    const limit = query?.limit ?? 100;
    const items = filtered.slice(offset, offset + limit);

    return {
      items,
      total: filtered.length,
      offset,
      limit,
    };
  }

  /**
   * @brief Reads a slice of raw artifact bytes for hex viewing.
   * @param reportId Artifact identifier.
   * @param offset Start byte offset.
   * @param length Length of slice to extract.
   * @return HexSlice or null if original artifact binary was not provided.
   */
  public async getHex(reportId: string, offset: number, length: number): Promise<HexSlice | null> {
    const bytes = this.artifactBytes.get(reportId);
    if (!bytes) {
      return null;
    }

    const safeOffset = Math.max(0, Math.min(offset, bytes.length));
    const safeLength = Math.max(0, Math.min(length, bytes.length - safeOffset));
    const slice = bytes.subarray(safeOffset, safeOffset + safeLength);

    return {
      offset: safeOffset,
      length: safeLength,
      totalSize: bytes.length,
      bytes: slice,
    };
  }

  /**
   * @brief Retrieves stored recent report summaries.
   * @return Array of ReportSummary objects.
   */
  public async listReports(): Promise<ReportSummary[]> {
    if (typeof window === "undefined" || !window.localStorage) {
      return Array.from(this.reports.values()).map(this.createSummary);
    }

    try {
      const raw = window.localStorage.getItem(this.STORAGE_KEY);
      if (!raw) return [];
      return JSON.parse(raw) as ReportSummary[];
    } catch {
      return [];
    }
  }

  /**
   * @brief Calculates severity metrics and creates a concise ReportSummary.
   * @param report Full AveroReport.
   * @return ReportSummary for index listing.
   */
  private createSummary(report: AveroReport): ReportSummary {
    const counts = {
      critical: 0,
      high: 0,
      medium: 0,
      low: 0,
      info: 0,
      total: report.findings.length,
    };

    for (const f of report.findings) {
      if (f.severity in counts) {
        counts[f.severity as keyof typeof counts]++;
      }
    }

    return {
      id: report.artifact.id,
      name: report.artifact.path.split(/[/\\]/).pop() || report.artifact.id.slice(0, 12),
      sha256: report.artifact.hashes.sha256,
      size: report.artifact.size,
      kinds: report.artifact.kinds,
      generated_at: report.generated_at,
      findingsCount: counts,
    };
  }

  /**
   * @brief Persists summary to browser local storage.
   * @param report Ingested AveroReport.
   */
  private saveRecentSummary(report: AveroReport): void {
    if (typeof window === "undefined" || !window.localStorage) return;

    try {
      const summary = this.createSummary(report);
      const existing = (JSON.parse(window.localStorage.getItem(this.STORAGE_KEY) || "[]") as ReportSummary[])
        .filter((s) => s.id !== summary.id);

      existing.unshift(summary);
      const trimmed = existing.slice(0, 10);
      window.localStorage.setItem(this.STORAGE_KEY, JSON.stringify(trimmed));
    } catch {
      // Ignore local storage quota limits gracefully
    }
  }
}
