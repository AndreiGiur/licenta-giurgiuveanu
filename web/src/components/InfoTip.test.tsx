import { describe, it, expect } from "vitest";
import { render, screen, fireEvent } from "@testing-library/react";
import { InfoTip } from "./InfoTip";
import { HELP } from "../help/helpContent";

describe("InfoTip", () => {
  it("randeaza un buton accesibil cu aria-label din topic", () => {
    render(<InfoTip topic="exposure-score" />);
    const btn = screen.getByRole("button", { name: /Scor de expunere/i });
    expect(btn).toBeInTheDocument();
    expect(btn).toHaveAttribute("aria-expanded", "false");
  });

  it("la click deschide popover-ul cu titlul si textul din dictionar", () => {
    render(<InfoTip topic="exposure-score" />);
    const btn = screen.getByRole("button");
    fireEvent.click(btn);
    expect(btn).toHaveAttribute("aria-expanded", "true");
    const entry = HELP["exposure-score"];
    expect(screen.getByText(entry.title)).toBeInTheDocument();
    expect(screen.getByText(entry.body)).toBeInTheDocument();
  });

  it("Escape inchide popover-ul", () => {
    render(<InfoTip topic="exposure-score" />);
    fireEvent.click(screen.getByRole("button"));
    expect(screen.getByText(HELP["exposure-score"].title)).toBeInTheDocument();
    fireEvent.keyDown(document, { key: "Escape" });
    expect(screen.queryByText(HELP["exposure-score"].title)).not.toBeInTheDocument();
  });

  it("accepta continut inline (title/body) peste dictionar", () => {
    render(<InfoTip title="Titlu custom" body="Corp custom" />);
    fireEvent.click(screen.getByRole("button"));
    expect(screen.getByText("Titlu custom")).toBeInTheDocument();
    expect(screen.getByText("Corp custom")).toBeInTheDocument();
  });
});
