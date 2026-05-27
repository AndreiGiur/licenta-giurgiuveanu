import { describe, it, expect } from "vitest";
import { render, screen } from "@testing-library/react";
import { ScoreGauge } from "./ScoreGauge";


describe("ScoreGauge", () => {
  it("randeaza valoarea finala dupa animatie (intre 0 si 100)", async () => {
    render(<ScoreGauge value={42} />);
    // Cifrele 4 si 2 sunt prezente in pagina (chiar daca animate, finalul e 42)
    // Asteptam scurt pentru framer-motion sa termine
    await new Promise(r => setTimeout(r, 1300));
    expect(screen.getByText("42")).toBeInTheDocument();
  });

  it("foloseste label-ul default '/ 100' cand prop label nu e furnizat", async () => {
    render(<ScoreGauge value={50} />);
    expect(screen.getByText("/ 100")).toBeInTheDocument();
  });

  it("accepta label custom", () => {
    render(<ScoreGauge value={50} label="punctaj" />);
    expect(screen.getByText("punctaj")).toBeInTheDocument();
  });

  it("aplica clasa de severitate 'high' pentru scor >= 70", () => {
    const { container } = render(<ScoreGauge value={85} />);
    expect(container.querySelector(".score-high")).toBeInTheDocument();
  });

  it("aplica clasa de severitate 'medium' pentru scor in [40, 70)", () => {
    const { container } = render(<ScoreGauge value={50} />);
    expect(container.querySelector(".score-medium")).toBeInTheDocument();
  });

  it("aplica clasa de severitate 'low' pentru scor in (0, 40)", () => {
    const { container } = render(<ScoreGauge value={15} />);
    expect(container.querySelector(".score-low")).toBeInTheDocument();
  });

  it("aplica clasa de severitate 'none' pentru scor = 0 (sistem curat)", () => {
    const { container } = render(<ScoreGauge value={0} />);
    expect(container.querySelector(".score-none")).toBeInTheDocument();
  });

  it("dimensiune SVG corespunde prop-ului size", () => {
    const { container } = render(<ScoreGauge value={50} size={200} />);
    const svg = container.querySelector("svg");
    expect(svg).toHaveAttribute("width", "200");
    expect(svg).toHaveAttribute("height", "200");
  });
});
