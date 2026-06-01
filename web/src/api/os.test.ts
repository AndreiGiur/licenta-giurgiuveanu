import { describe, it, expect } from "vitest";
import { detectOS } from "./os";

describe("detectOS", () => {
  it("detecteaza Windows", () => {
    expect(detectOS("Mozilla/5.0 (Windows NT 10.0; Win64; x64)")).toBe("windows");
  });
  it("detecteaza Linux", () => {
    expect(detectOS("Mozilla/5.0 (X11; Linux x86_64)")).toBe("linux");
  });
  it("Android nu e tratat ca Linux desktop", () => {
    expect(detectOS("Mozilla/5.0 (Linux; Android 13)")).toBe("other");
  });
  it("alt OS -> other", () => {
    expect(detectOS("Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15)")).toBe("other");
  });
});
