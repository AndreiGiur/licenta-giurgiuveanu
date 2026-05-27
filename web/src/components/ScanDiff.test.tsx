import { describe, it, expect, vi, beforeEach } from "vitest";
import { render, screen, waitFor } from "@testing-library/react";
import { ScanDiff } from "./ScanDiff";

// Mock-uim apelul la API exposure pentru a evita HTTP real
vi.mock("../api/exposure", () => ({
  getScanDiff: vi.fn(),
}));

import { getScanDiff } from "../api/exposure";


function mkDiff(overrides: object = {}) {
  return {
    from_scan_id: 10,
    to_scan_id: 11,
    from_score: 40,
    to_score: 25,
    delta: -15,
    added: [],
    fixed: [],
    unchanged: [],
    ...overrides,
  };
}


describe("ScanDiff", () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it("afiseaza loading state la mount", () => {
    (getScanDiff as ReturnType<typeof vi.fn>).mockReturnValue(new Promise(() => {}));
    render(<ScanDiff scanId={11} />);
    expect(screen.getByText(/calculeaza/i)).toBeInTheDocument();
  });

  it("randeaza 3 coloane (Adaugate / Rezolvate / Nemodificate)", async () => {
    (getScanDiff as ReturnType<typeof vi.fn>).mockResolvedValue(mkDiff());
    render(<ScanDiff scanId={11} />);
    await waitFor(() => {
      expect(screen.getByText(/Adaugate/i)).toBeInTheDocument();
    });
    expect(screen.getByText(/Rezolvate/i)).toBeInTheDocument();
    expect(screen.getByText(/Nemodificate/i)).toBeInTheDocument();
  });

  it("afiseaza delta 'imbunatatire' cand scor scazut", async () => {
    (getScanDiff as ReturnType<typeof vi.fn>).mockResolvedValue(mkDiff({ delta: -15 }));
    render(<ScanDiff scanId={11} />);
    await waitFor(() => {
      expect(screen.getByText(/imbunatatire/i)).toBeInTheDocument();
    });
  });

  it("afiseaza delta 'regresie' cand scor crescut", async () => {
    (getScanDiff as ReturnType<typeof vi.fn>).mockResolvedValue(mkDiff({
      delta: 10, to_score: 50,
    }));
    render(<ScanDiff scanId={11} />);
    await waitFor(() => {
      expect(screen.getByText(/regresie/i)).toBeInTheDocument();
    });
  });

  it("afiseaza 'neschimbat' cand delta = 0", async () => {
    (getScanDiff as ReturnType<typeof vi.fn>).mockResolvedValue(mkDiff({ delta: 0, to_score: 40 }));
    render(<ScanDiff scanId={11} />);
    await waitFor(() => {
      expect(screen.getByText(/neschimbat/i)).toBeInTheDocument();
    });
  });

  it("listeaza finding-urile added si fixed cu rule_id si severitate", async () => {
    (getScanDiff as ReturnType<typeof vi.fn>).mockResolvedValue(mkDiff({
      added: [{ rule_id: "NEW-RULE-1", title: "Probema noua", severity: "high" }],
      fixed: [{ rule_id: "OLD-RULE-1", title: "Problema rezolvata", severity: "medium" }],
    }));
    render(<ScanDiff scanId={11} />);
    await waitFor(() => {
      expect(screen.getByText("NEW-RULE-1")).toBeInTheDocument();
    });
    expect(screen.getByText("OLD-RULE-1")).toBeInTheDocument();
    expect(screen.getByText(/Probema noua/i)).toBeInTheDocument();
    expect(screen.getByText(/Problema rezolvata/i)).toBeInTheDocument();
  });

  it("trimite previousId catre getScanDiff cand e furnizat", async () => {
    (getScanDiff as ReturnType<typeof vi.fn>).mockResolvedValue(mkDiff());
    render(<ScanDiff scanId={11} previousId={5} />);
    await waitFor(() => {
      expect(getScanDiff).toHaveBeenCalledWith(11, 5);
    });
  });

  it("afiseaza mesaj de eroare cand getScanDiff esueaza", async () => {
    (getScanDiff as ReturnType<typeof vi.fn>).mockRejectedValue(new Error("nu exista scanare anterioara"));
    render(<ScanDiff scanId={11} />);
    await waitFor(() => {
      expect(screen.getByText(/nu exista scanare anterioara/i)).toBeInTheDocument();
    });
  });
});
