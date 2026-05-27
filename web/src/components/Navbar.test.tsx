import { describe, it, expect, vi, beforeEach } from "vitest";
import { render, screen, waitFor } from "@testing-library/react";
import { MemoryRouter } from "react-router-dom";
import Navbar from "./Navbar";

vi.mock("../api/auth", () => ({
  fetchMe: vi.fn(),
  logoutUser: vi.fn(),
}));

vi.mock("./ThemeToggle", () => ({
  ThemeToggle: () => <button data-testid="theme-toggle">Toggle</button>,
}));

import { fetchMe } from "../api/auth";


function renderNav() {
  return render(
    <MemoryRouter initialEntries={["/dashboard"]}>
      <Navbar />
    </MemoryRouter>
  );
}


describe("Navbar", () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it("afiseaza brand-ul VulnWatch", () => {
    (fetchMe as ReturnType<typeof vi.fn>).mockResolvedValue(null);
    renderNav();
    expect(screen.getByText("VulnWatch")).toBeInTheDocument();
  });

  it("afiseaza link-urile Dashboard, Dispozitive, Profil", async () => {
    (fetchMe as ReturnType<typeof vi.fn>).mockResolvedValue({ id: 1, email: "u@test.com" });
    renderNav();
    expect(screen.getByText("Dashboard")).toBeInTheDocument();
    expect(screen.getByText("Dispozitive")).toBeInTheDocument();
    expect(screen.getByText("Profil")).toBeInTheDocument();
  });

  it("NU afiseaza butonul Admin pentru user normal", async () => {
    (fetchMe as ReturnType<typeof vi.fn>).mockResolvedValue({ id: 1, email: "u@test.com", role: "user" });
    renderNav();
    await waitFor(() => {
      expect(screen.queryByText(/Admin/)).not.toBeInTheDocument();
    });
  });

  it("AFISEAZA butonul Admin pentru user cu role=admin", async () => {
    (fetchMe as ReturnType<typeof vi.fn>).mockResolvedValue({
      id: 1, email: "admin@test.com", role: "admin",
    });
    renderNav();
    await waitFor(() => {
      expect(screen.getByText(/Admin/)).toBeInTheDocument();
    });
  });

  it("afiseaza Logout cand user autentificat", async () => {
    (fetchMe as ReturnType<typeof vi.fn>).mockResolvedValue({ id: 1, email: "u@test.com" });
    renderNav();
    await waitFor(() => {
      expect(screen.getByText("Logout")).toBeInTheDocument();
    });
  });

  it("NU afiseaza Logout cand fetchMe esueaza (neautentificat)", async () => {
    (fetchMe as ReturnType<typeof vi.fn>).mockRejectedValue(new Error("401"));
    renderNav();
    await waitFor(() => {
      expect(screen.queryByText("Logout")).not.toBeInTheDocument();
    });
  });
});
