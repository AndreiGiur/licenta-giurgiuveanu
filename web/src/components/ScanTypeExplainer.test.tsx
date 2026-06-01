import { describe, it, expect } from "vitest";
import { render, screen } from "@testing-library/react";
import { ScanTypeExplainer } from "./ScanTypeExplainer";

describe("ScanTypeExplainer", () => {
  it("standard: arata durata + ce colecteaza", () => {
    render(<ScanTypeExplainer type="standard" />);
    expect(screen.getByText(/45-90s/i)).toBeInTheDocument();
    expect(screen.getByText(/porturi/i)).toBeInTheDocument();
  });
  it("deep: mentioneaza nmap agresiv / CVE", () => {
    render(<ScanTypeExplainer type="deep" />);
    expect(screen.getByText(/CVE|nmap agresiv/i)).toBeInTheDocument();
  });
  it("advanced: mentioneaza nmap moderat", () => {
    render(<ScanTypeExplainer type="advanced" />);
    expect(screen.getByText(/nmap moderat/i)).toBeInTheDocument();
  });
});
