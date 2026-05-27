import { describe, it, expect } from "vitest";
import { render } from "@testing-library/react";
import { UserAvatar } from "./UserAvatar";


describe("UserAvatar", () => {
  it("afiseaza initiala emailului cand nu exista poza Google", () => {
    const { container } = render(<UserAvatar email="maria.popescu@example.com" pictureUrl={null} />);
    expect(container.textContent).toContain("M");
  });

  it("randeaza tag <img> cand pictureUrl e furnizat", () => {
    const url = "https://example.com/picture.png";
    const { container } = render(<UserAvatar email="test@example.com" pictureUrl={url} />);
    const img = container.querySelector("img");
    expect(img).toBeInTheDocument();
    expect(img?.src).toBe(url);
  });

  it("foloseste size custom cand e furnizat", () => {
    const { container } = render(<UserAvatar email="x@y.com" pictureUrl={null} size={64} />);
    // Avatarul are width si height = size
    const root = container.firstChild as HTMLElement;
    expect(root.style.width).toBe("64px");
    expect(root.style.height).toBe("64px");
  });
});
