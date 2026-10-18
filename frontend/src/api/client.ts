/**
 * Typed HTTP Client for AI Data Leak Guardian API.
 * Uses relative /api paths which are proxied by Vite in dev and served directly in prod.
 */

import {
  AnalyzeResponse,
  EvaluationMetricsResponse,
  LiveBenchmarkResponse,
  PresetsResponse,
  RestoreResponse,
  SessionResetResponse,
  SystemStatus,
} from "./types";

const BASE_URL = "/api";

class ApiError extends Error {
  constructor(public status: number, message: string) {
    super(message);
    this.name = "ApiError";
  }
}

async function request<T>(endpoint: string, options: RequestInit = {}): Promise<T> {
  const url = `${BASE_URL}${endpoint}`;
  const headers = {
    "Content-Type": "application/json",
    Accept: "application/json",
    ...options.headers,
  };

  try {
    const response = await fetch(url, {
      ...options,
      headers,
    });

    if (!response.ok) {
      let detail = `Request failed with status ${response.status}`;
      try {
        const errorData = await response.json();
        if (errorData?.detail) {
          detail = errorData.detail;
        }
      } catch {
        // Fallback to text
        const text = await response.text();
        if (text) detail = text;
      }
      throw new ApiError(response.status, detail);
    }

    return (await response.json()) as T;
  } catch (error) {
    if (error instanceof ApiError) {
      throw error;
    }
    // Network or client connection error
    throw new ApiError(0, "Unable to connect to Data Leak Guardian backend. Is server.py running?");
  }
}

export const api = {
  /**
   * Fetch live engine and detector readiness.
   */
  getStatus: () => request<SystemStatus>("/status"),

  /**
   * Run full inspection, risk scoring, and reversible redaction.
   */
  analyze: (text: string, sessionId?: string) =>
    request<AnalyzeResponse>("/analyze", {
      method: "POST",
      body: JSON.stringify({ text, session_id: sessionId }),
    }),

  /**
   * Locally restore recognized placeholders in simulated response.
   */
  restore: (sessionId: string, aiResponse: string) =>
    request<RestoreResponse>("/restore", {
      method: "POST",
      body: JSON.stringify({ session_id: sessionId, ai_response: aiResponse }),
    }),

  /**
   * Purge session vault mappings on backend.
   */
  resetSession: (sessionId: string) =>
    request<SessionResetResponse>("/session/reset", {
      method: "POST",
      body: JSON.stringify({ session_id: sessionId }),
    }),

  /**
   * Get verified synthetic presets.
   */
  getPresets: () => request<PresetsResponse>("/presets"),

  /**
   * Read stored evaluation report and model manifest.
   */
  getEvaluationMetrics: () => request<EvaluationMetricsResponse>("/evaluation/metrics"),

  /**
   * Run live fixture benchmark on synthetic test datasets.
   */
  runLiveBenchmark: () =>
    request<LiveBenchmarkResponse>("/evaluation/benchmark", {
      method: "POST",
    }),
};
