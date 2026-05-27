import { describe, it, expect, vi, beforeEach } from "vitest";
import { render, screen, fireEvent, waitFor } from "@testing-library/react";
import { GoogleButton } from "./GoogleButton";

vi.mock("../api/auth", () => ({
  getGoogleAuthUrl: vi.fn(),
}));

import { getGoogleAuthUrl } from "../api/auth";


describe("GoogleButton", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    // Stub window.location.href ca să nu redirectionăm efectiv în teste
    Object.defineProperty(window, "location", {
      value: { href: "" },
      writable: true,
    });
  });

  it("afiseaza label-ul default 'Continuă cu Google'", () => {
    render(<GoogleButton />);
    expect(screen.getByText(/Continuă cu Google/)).toBeInTheDocument();
  });

  it("accepta label custom", () => {
    render(<GoogleButton label="Conectează-te" />);
    expect(screen.getByText("Conectează-te")).toBeInTheDocument();
  });

  it("randeaza logo-ul Google ca SVG cu 4 paths colorate", () => {
    const { container } = render(<GoogleButton />);
    const svg = container.querySelector("svg");
    expect(svg).toBeInTheDocument();
    expect(svg?.querySelectorAll("path")).toHaveLength(4);
  });

  it("la click apeleaza getGoogleAuthUrl si redirectioneaza", async () => {
    (getGoogleAuthUrl as ReturnType<typeof vi.fn>).mockResolvedValue({
      auth_url: "https://accounts.google.com/oauth2/v2/auth?...",
      state: "abc",
    });
    render(<GoogleButton />);
    fireEvent.click(screen.getByRole("button"));
    await waitFor(() => {
      expect(getGoogleAuthUrl).toHaveBeenCalled();
    });
    await waitFor(() => {
      expect(window.location.href).toContain("accounts.google.com");
    });
  });

  it("afiseaza 'Se redirecționează...' in timpul loading", async () => {
    (getGoogleAuthUrl as ReturnType<typeof vi.fn>).mockReturnValue(new Promise(() => {}));
    render(<GoogleButton />);
    fireEvent.click(screen.getByRole("button"));
    await waitFor(() => {
      expect(screen.getByText(/Se redirecționează/)).toBeInTheDocument();
    });
  });

  it("apeleaza onError la esec si reseteaza loading", async () => {
    const onError = vi.fn();
    (getGoogleAuthUrl as ReturnType<typeof vi.fn>).mockRejectedValue(new Error("Network down"));
    render(<GoogleButton onError={onError} />);
    fireEvent.click(screen.getByRole("button"));
    await waitFor(() => {
      expect(onError).toHaveBeenCalledWith("Network down");
    });
  });
});
