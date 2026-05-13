import { apiDelete, apiGet, apiPost } from "./http";

/**
 * Frontend-ul NU mai stocheaza tokenul de sesiune. Backend-ul seteaza un
 * cookie HttpOnly la /auth/login si il sterge la /auth/logout. Browser-ul
 * il trimite automat la fiecare cerere (datorita `credentials: "include"`).
 */

export type Me = {
  id: number;
  email: string;
  google_picture_url?: string | null;
  auth_provider?: "password" | "google" | "both";
};

export async function registerUser(input: { email: string; password: string }): Promise<Me> {
  return apiPost<typeof input, Me>("/auth/register", input);
}

export async function loginUser(input: { email: string; password: string }): Promise<void> {
  // Raspunsul contine si session_token, dar nu il folosim in browser
  // (cookie-ul HttpOnly e sursa de adevar).
  await apiPost<typeof input, { session_token: string }>("/auth/login", input);
}

export async function fetchMe(): Promise<Me> {
  return apiGet<Me>("/auth/me");
}

export async function logoutUser(): Promise<void> {
  await apiDelete<{ ok: boolean }>("/auth/logout");
}

export async function getGoogleAuthUrl(): Promise<{ auth_url: string; state: string }> {
  return apiGet<{ auth_url: string; state: string }>("/auth/google/url");
}
