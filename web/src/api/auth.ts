import { http } from "./http";

const TOKEN_KEY = "session_token";

export function saveSessionToken(token: string): void {
  localStorage.setItem(TOKEN_KEY, token);
}

export function getSessionToken(): string | null {
  return localStorage.getItem(TOKEN_KEY);
}

export function clearSessionToken(): void {
  localStorage.removeItem(TOKEN_KEY);
}

export async function registerUser(input: { email: string; password: string }): Promise<{ id: number; email: string }> {
  return http<{ id: number; email: string }>("/api/v1/auth/register", {
    method: "POST",
    body: input,
  });
}

export async function loginUser(input: { email: string; password: string }): Promise<{ session_token: string }> {
  return http<{ session_token: string }>("/api/v1/auth/login", {
    method: "POST",
    body: input,
  });
}

export async function fetchMe(): Promise<{ id: number; email: string }> {
  const tok = getSessionToken();
  if (!tok) throw new Error("Missing session token");

  return http<{ id: number; email: string }>("/api/v1/auth/me", {
    method: "GET",
    headers: {
      "X-Session-Token": tok,
    },
  });
}

export async function logoutUser(): Promise<void> {
  const tok = getSessionToken();
  if (!tok) throw new Error("Missing session token");

  await http<{ ok: boolean }>("/api/v1/auth/logout", {
    method: "DELETE",
    headers: {
      "X-Session-Token": tok,
    },
  });
  clearSessionToken();
}
