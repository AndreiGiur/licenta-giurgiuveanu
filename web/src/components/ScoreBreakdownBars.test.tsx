import { describe, it, expect } from "vitest";
import { render, screen } from "@testing-library/react";
import { ScoreBreakdownBars } from "./ScoreBreakdownBars";
import type { ScoreBreakdown } from "../api/types";


describe("ScoreBreakdownBars", () => {
  const sampleBreakdown: ScoreBreakdown = {
    critical_risk: 80,
    network_exposure: 30,
    hygiene: 50,
    activity: 10,
  };

  it("randeaza 4 randuri pentru fiecare categorie", () => {
    const { container } = render(<ScoreBreakdownBars breakdown={sampleBreakdown} />);
    const rows = container.querySelectorAll(".score-breakdown-row");
    expect(rows).toHaveLength(4);
  });

  it("afiseaza valorile numerice ale fiecarei categorii", () => {
    render(<ScoreBreakdownBars breakdown={sampleBreakdown} />);
    expect(screen.getByText("80")).toBeInTheDocument();
    expect(screen.getByText("30")).toBeInTheDocument();
    expect(screen.getByText("50")).toBeInTheDocument();
    expect(screen.getByText("10")).toBeInTheDocument();
  });

  it("afiseaza ponderea fiecarei categorii (40%, 30%, 20%, 10%)", () => {
    render(<ScoreBreakdownBars breakdown={sampleBreakdown} />);
    expect(screen.getByText("40%")).toBeInTheDocument();
    expect(screen.getByText("30%")).toBeInTheDocument();
    expect(screen.getByText("20%")).toBeInTheDocument();
    expect(screen.getByText("10%")).toBeInTheDocument();
  });

  it("afiseaza label-urile in romana pentru fiecare categorie", () => {
    render(<ScoreBreakdownBars breakdown={sampleBreakdown} />);
    expect(screen.getByText(/Risc critic/i)).toBeInTheDocument();
    expect(screen.getByText(/Expunere/i)).toBeInTheDocument();
    expect(screen.getByText(/Igien/i)).toBeInTheDocument();
    expect(screen.getByText(/Activitate/i)).toBeInTheDocument();
  });

  it("aplica clasa 'compact' cand prop compact=true", () => {
    const { container } = render(<ScoreBreakdownBars breakdown={sampleBreakdown} compact />);
    expect(container.querySelector(".score-breakdown-compact")).toBeInTheDocument();
  });

  it("nu aplica clasa 'compact' cand prop compact=false (default)", () => {
    const { container } = render(<ScoreBreakdownBars breakdown={sampleBreakdown} />);
    expect(container.querySelector(".score-breakdown-compact")).not.toBeInTheDocument();
  });

  it("randeaza 0 ca valoare pentru toate categoriile cand sistem curat", () => {
    const zero: ScoreBreakdown = { critical_risk: 0, network_exposure: 0, hygiene: 0, activity: 0 };
    const { container } = render(<ScoreBreakdownBars breakdown={zero} />);
    const values = container.querySelectorAll(".score-breakdown-value");
    expect(values).toHaveLength(4);
    values.forEach(v => expect(v.textContent).toBe("0"));
  });
});
