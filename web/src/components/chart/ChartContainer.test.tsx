import { describe, it, expect } from "vitest";
import { render } from "@testing-library/react";
import { ChartContainer } from "./ChartContainer";

class RO { constructor(_: ResizeObserverCallback) {} observe() {} unobserve() {} disconnect() {} }
// eslint-disable-next-line @typescript-eslint/no-explicit-any
(globalThis as any).ResizeObserver = RO;

describe("ChartContainer", () => {
  it("randeaza copiii si seteaza --color-<key> din config", () => {
    const { container } = render(
      <ChartContainer config={{ out: { label: "Iesit", color: "#2563eb" } }} height={100}>
        <div data-testid="child" />
      </ChartContainer>,
    );
    const root = container.querySelector(".chart-container") as HTMLElement;
    expect(root).toBeTruthy();
    expect(root.style.getPropertyValue("--color-out")).toBe("#2563eb");
  });
});
