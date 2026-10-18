import { describe, it, expect, vi, beforeEach } from "vitest";
import { render, screen, waitFor, fireEvent } from "@testing-library/react";
import App from "../App";
import { api } from "../api/client";

vi.mock("../api/client", () => ({
  api: {
    getStatus: vi.fn(),
    getPresets: vi.fn(),
    getEvaluationMetrics: vi.fn(),
    analyze: vi.fn(),
    restore: vi.fn(),
    resetSession: vi.fn(),
    runLiveBenchmark: vi.fn(),
  },
}));

describe("AI Data Leak Guardian — Primary Analysis & Security Invariants", () => {
  beforeEach(() => {
    vi.clearAllMocks();

    (api.getStatus as any).mockResolvedValue({
      backend_status: "ready",
      rules_active: true,
      ml_available: true,
      ml_model_name: "spacy_blank_en_ner",
      active_vault_sessions: 1,
      platform: "win32",
      python_version: "3.13.14",
    });

    (api.getPresets as any).mockResolvedValue({
      presets: [
        {
          id: "preset_1",
          title: "Preset 1: Full Incident (PII + DB URL + API Key)",
          content: "Contact dev at alex.mercer@mockcorp.internal with api_key='sk_live_secret999'.",
        },
      ],
    });

    (api.getEvaluationMetrics as any).mockResolvedValue({ available: false });
  });

  it("loads a synthetic preset into the inspection workspace", async () => {
    render(<App />);

    await waitFor(() => {
      expect(screen.getByRole("combobox")).toBeInTheDocument();
    });

    const select = screen.getByRole("combobox");
    fireEvent.change(select, { target: { value: "preset_1" } });

    const loadBtn = screen.getByText("Load Preset");
    fireEvent.click(loadBtn);

    const textarea = screen.getByLabelText("Input content for inspection") as HTMLTextAreaElement;
    expect(textarea.value).toContain("alex.mercer@mockcorp.internal");
    expect(textarea.value).toContain("sk_live_secret999");
  });

  it("executes analysis, displays risk assessment, and strictly excludes raw secrets from findings table", async () => {
    const rawSecret = "sk_live_supersecret_key_123456789";
    const rawEmail = "victim.corp@example.com";

    (api.analyze as any).mockResolvedValue({
      session_id: "test_session_safe",
      findings: [
        {
          entity_type: "EMAIL",
          start: 11,
          end: 34,
          span_length: 23,
          severity: "Medium",
          rule_id: "regex:email_rfc5322",
          confidence: 0.98,
          description: "Detected email address (length 23)",
          metadata: {},
        },
        {
          entity_type: "API_KEY",
          start: 49,
          end: 82,
          span_length: 33,
          severity: "Critical",
          rule_id: "secret:api_key_assignment",
          confidence: 0.95,
          description: "Detected API key or secret token assignment",
          metadata: {},
        },
      ],
      risk: {
        risk_level: "Critical",
        reasons: [
          "CRITICAL: Detected 1 confirmed credential or secret finding(s). Transmission would cause immediate credential exposure.",
        ],
        findings_count: 2,
        critical_count: 1,
        high_count: 0,
        medium_count: 1,
        low_count: 0,
      },
      redaction: {
        session_id: "test_session_safe",
        masked_text: "Contact at [EMAIL_1] with api_key='[API_KEY_1]'.",
        placeholders_count: 2,
        unique_placeholders: 2,
        findings_redacted: 2,
      },
    });

    render(<App />);

    const textarea = screen.getByLabelText("Input content for inspection");
    fireEvent.change(textarea, {
      target: { value: `Contact at ${rawEmail} with api_key='${rawSecret}'.` },
    });

    const analyzeBtn = screen.getByText("🛡️ Analyze & Redact");
    fireEvent.click(analyzeBtn);

    await waitFor(() => {
      // Risk assessment displayed
      expect(screen.getByText("CRITICAL EXPOSURE RISK")).toBeInTheDocument();
      expect(screen.getByText("2. Structured Findings (2)")).toBeInTheDocument();
      expect(screen.getByText("3. Sanitized Prompt (Safe for External AI)")).toBeInTheDocument();
      expect(screen.getByText("Contact at [EMAIL_1] with api_key='[API_KEY_1]'.")).toBeInTheDocument();
    });

    // CRITICAL SECURITY INVARIANT:
    // Assert that the raw secret value does NOT appear anywhere in the Findings table DOM!
    const tableElement = screen.getByRole("table");
    expect(tableElement).toBeInTheDocument();
    expect(tableElement.textContent).not.toContain(rawSecret);
    expect(tableElement.textContent).not.toContain(rawEmail);
  });

  it("marks findings stale and veils previous results when user modifies input", async () => {
    (api.analyze as any).mockResolvedValue({
      session_id: "sess_stale_test",
      findings: [],
      risk: {
        risk_level: "Low",
        reasons: ["LOW: Clean text"],
        findings_count: 0,
        critical_count: 0,
        high_count: 0,
        medium_count: 0,
        low_count: 0,
      },
      redaction: {
        session_id: "sess_stale_test",
        masked_text: "Initial text",
        placeholders_count: 0,
        unique_placeholders: 0,
        findings_redacted: 0,
      },
    });

    render(<App />);

    const textarea = screen.getByLabelText("Input content for inspection");
    fireEvent.change(textarea, { target: { value: "Initial text" } });
    fireEvent.click(screen.getByText("🛡️ Analyze & Redact"));

    await waitFor(() => {
      expect(screen.getByText("LOW EXPOSURE RISK")).toBeInTheDocument();
    });

    // Now modify the textarea without clicking analyze
    fireEvent.change(textarea, { target: { value: "Initial text with new edits" } });

    // The staleness alert banner must appear
    expect(
      screen.getByText(/Input was modified after analysis:/i)
    ).toBeInTheDocument();

    // The old risk card must be veiled
    expect(screen.queryByText("LOW EXPOSURE RISK")).not.toBeInTheDocument();
  });

  it("handles simulated response restoration and foreign token preservation", async () => {
    (api.restore as any).mockResolvedValue({
      session_id: "sess_restore_test",
      restored_text: "Acknowledged for user@example.com. Foreign: [FOREIGN_KEY_99].",
      restored_placeholders: ["[EMAIL_1]"],
      unrestored_placeholders: ["[FOREIGN_KEY_99]"],
      is_fully_restored: false,
    });

    render(<App />);

    const simulatedInput = screen.getByLabelText("Simulated AI response input");
    fireEvent.change(simulatedInput, {
      target: { value: "Acknowledged for [EMAIL_1]. Foreign: [FOREIGN_KEY_99]." },
    });

    const restoreBtn = screen.getByText("🔓 Restore Response Locally");
    fireEvent.click(restoreBtn);

    await waitFor(() => {
      expect(screen.getByText("Locally Decoded Output:")).toBeInTheDocument();
      expect(
        screen.getByText("Acknowledged for user@example.com. Foreign: [FOREIGN_KEY_99].")
      ).toBeInTheDocument();
      expect(screen.getByText("Restored in This Session (1)")).toBeInTheDocument();
      expect(screen.getByText("Unknown / Preserved Untouched (1)")).toBeInTheDocument();
    });
  });

  it("purges vault mappings upon clicking Purge Vault Mappings", async () => {
    (api.resetSession as any).mockResolvedValue({
      session_id: "sess_purge",
      cleared: true,
      active_placeholder_count: 0,
    });

    render(<App />);

    const purgeBtn = screen.getByText("Purge Vault Mappings");
    fireEvent.click(purgeBtn);

    await waitFor(() => {
      expect(api.resetSession).toHaveBeenCalled();
    });
  });
});
