import { describe, it, expect, vi, beforeEach } from "vitest";
import { render, screen, waitFor, fireEvent } from "@testing-library/react";
import App from "../App";
import { api } from "../api/client";

// Mock the API client
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

describe("AI Data Leak Guardian — App Shell & Navigation", () => {
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
          content: "Hello team, my name is Alex Mercer. Contact alex.mercer@mockcorp.internal.",
        },
      ],
    });

    (api.getEvaluationMetrics as any).mockResolvedValue({
      available: true,
      status_message: "Verified benchmark metrics loaded.",
      matching_policy: "exact-span",
      total_test_records: 2,
      hybrid: {
        overall_micro: {
          category: "OVERALL_MICRO",
          true_positives: 3,
          false_positives: 0,
          false_negatives: 2,
          precision: 1.0,
          recall: 0.6,
          f1_score: 0.75,
        },
        overall_macro_f1: 0.6667,
        per_entity: {},
      },
    });
  });

  it("renders header branding, IBM Z context, and live status badges", async () => {
    render(<App />);

    expect(screen.getByText("AI Data Leak Guardian")).toBeInTheDocument();
    expect(
      screen.getByText("AI Secured — Innovation Without Exposure")
    ).toBeInTheDocument();

    await waitFor(() => {
      expect(screen.getByTestId("status-backend")).toHaveTextContent("Backend: Ready");
      expect(screen.getByTestId("status-rules")).toHaveTextContent("Rules: Active");
      expect(screen.getByTestId("status-ml")).toHaveTextContent("Hybrid: spaCy NER");
    });
  });

  it("switches navigation tabs to Taxonomy and Architecture views correctly", async () => {
    render(<App />);

    // Wait for initial fetch to settle
    await waitFor(() => {
      expect(screen.getByTestId("status-backend")).toBeInTheDocument();
    });

    // Click Taxonomy tab
    const taxonomyTab = screen.getByText("Rules & Detection Taxonomy");
    fireEvent.click(taxonomyTab);

    expect(
      screen.getByText("Detection Engine Taxonomy & Rule Reference")
    ).toBeInTheDocument();
    expect(screen.getByText("PII Rules (6)")).toBeInTheDocument();

    // Click Security Architecture tab
    const archTab = screen.getByText("Security Model & HSM Bounds");
    fireEvent.click(archTab);

    expect(
      screen.getByText("Security Architecture & Cryptographic Vault Boundaries")
    ).toBeInTheDocument();
    expect(screen.getByText("1. Zero External AI Transmission")).toBeInTheDocument();
  });
});
