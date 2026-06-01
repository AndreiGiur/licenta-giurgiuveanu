import { describe, it, expect, vi } from "vitest";
import { render, screen, fireEvent } from "@testing-library/react";
import { DeviceSidebar } from "./DeviceSidebar";

const devices = [
  { id: 1, device_uid: "pc1", name: "PC One", is_online: true, lastScore: 42, scanCount: 3 },
  { id: 2, device_uid: "pc2", name: "PC Two", is_online: false, lastScore: null, scanCount: 0 },
];

describe("DeviceSidebar", () => {
  it("listeaza device-urile", () => {
    render(<DeviceSidebar devices={devices} selectedUid="pc1" onSelect={() => {}} />);
    expect(screen.getByText("PC One")).toBeInTheDocument();
    expect(screen.getByText("PC Two")).toBeInTheDocument();
  });
  it("apeleaza onSelect la click", () => {
    const onSelect = vi.fn();
    render(<DeviceSidebar devices={devices} selectedUid="pc1" onSelect={onSelect} />);
    fireEvent.click(screen.getByText("PC Two"));
    expect(onSelect).toHaveBeenCalledWith("pc2");
  });
  it("empty state cand nu sunt device-uri", () => {
    render(<DeviceSidebar devices={[]} selectedUid={null} onSelect={() => {}} />);
    expect(screen.getByText(/niciun dispozitiv/i)).toBeInTheDocument();
  });
});
