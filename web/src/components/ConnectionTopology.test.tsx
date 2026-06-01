import { describe, it, expect } from "vitest";
import { render, screen } from "@testing-library/react";
import { ConnectionTopology } from "./ConnectionTopology";

describe("ConnectionTopology", () => {
  it("afiseaza cele 3 noduri", () => {
    render(<ConnectionTopology online={true} lastHeartbeat={new Date().toISOString()} scanActive={false} />);
    expect(screen.getByText(/Agent/i)).toBeInTheDocument();
    expect(screen.getByText(/Backend/i)).toBeInTheDocument();
    expect(screen.getByText(/Platform/i)).toBeInTheDocument();
  });

  it("marcheaza agentul Offline cand online=false", () => {
    render(<ConnectionTopology online={false} lastHeartbeat={null} scanActive={false} />);
    expect(screen.getByText(/Offline/i)).toBeInTheDocument();
  });

  it("marcheaza Online cand online=true", () => {
    render(<ConnectionTopology online={true} lastHeartbeat={new Date().toISOString()} scanActive={false} />);
    expect(screen.getByText(/Online/i)).toBeInTheDocument();
  });
});
