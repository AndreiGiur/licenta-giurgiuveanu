import { describe, it, expect, vi, beforeEach } from "vitest";
import { render, screen, waitFor } from "@testing-library/react";

vi.mock("../api/exposure", () => ({ getAgentDownloadInfo: vi.fn() }));
vi.mock("../api/http", () => ({ API_BASE_URL: "/api/v1" }));

import { getAgentDownloadInfo } from "../api/exposure";
import { AgentDownloadBanner } from "./AgentDownloadBanner";
const m = getAgentDownloadInfo as ReturnType<typeof vi.fn>;

describe("AgentDownloadBanner", () => {
  beforeEach(() => vi.clearAllMocks());

  it("afiseaza titlul de instalare agent", async () => {
    m.mockResolvedValue({ windows: { available: true, size_bytes: 28000000 }, linux: { available: false, size_bytes: null } });
    render(<AgentDownloadBanner />);
    expect(screen.getByText(/Instaleaza VulnWatch Agent/i)).toBeInTheDocument();
  });

  it("afiseaza butonul de descarcare cand build-ul e disponibil", async () => {
    m.mockResolvedValue({ windows: { available: true, size_bytes: 28000000 }, linux: { available: false, size_bytes: null } });
    render(<AgentDownloadBanner />);
    await waitFor(() => {
      const link = screen.getByRole("link", { name: /Descarca/i });
      expect(link).toHaveAttribute("href", expect.stringContaining("/agent/download/windows"));
    });
  });

  it("mesaj cand build-ul lipseste", async () => {
    m.mockResolvedValue({ windows: { available: false, size_bytes: null }, linux: { available: false, size_bytes: null } });
    render(<AgentDownloadBanner />);
    await waitFor(() => {
      expect(screen.getByText(/indisponibil/i)).toBeInTheDocument();
    });
  });
});
