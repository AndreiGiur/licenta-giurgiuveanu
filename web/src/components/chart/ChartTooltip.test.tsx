import { describe, it, expect } from "vitest";
import { render, screen } from "@testing-library/react";
import { ChartTooltip } from "./ChartTooltip";

const config = {
  out: { label: "Iesit", color: "#2563eb" },
  in: { label: "Intrat", color: "#0d9488" },
};

describe("ChartTooltip", () => {
  it("inactiv → null", () => {
    const { container } = render(<ChartTooltip config={config} active={false} payload={[]} />);
    expect(container.firstChild).toBeNull();
  });
  it("activ → label + randuri din config cu valoare formatata", () => {
    render(<ChartTooltip config={config} active
      payload={[{ dataKey: "out", value: 12.5 }, { dataKey: "in", value: 3 }]}
      labelFormatter={() => "14:20"} valueFormatter={(v) => `${v} KB/s`} />);
    expect(screen.getByText("14:20")).toBeInTheDocument();
    expect(screen.getByText("Iesit")).toBeInTheDocument();
    expect(screen.getByText("12.5 KB/s")).toBeInTheDocument();
    expect(screen.getByText("Intrat")).toBeInTheDocument();
  });
});
