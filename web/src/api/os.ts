/** Detectia OS-ului clientului din user-agent, pentru a oferi artefactul de
 *  descarcare potrivit (agent Windows .exe vs binar Linux). */
export type ClientOS = "windows" | "linux" | "other";

export function detectOS(ua: string = navigator.userAgent): ClientOS {
  const s = ua.toLowerCase();
  if (s.includes("windows")) return "windows";
  // "x11" prinde majoritatea desktop-urilor Linux; excludem Android (mobil).
  if ((s.includes("linux") || s.includes("x11")) && !s.includes("android")) {
    return "linux";
  }
  return "other";
}
