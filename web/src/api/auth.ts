import { apiGet, apiPost } from "./client";

export type RegisterRequest = { email: string; password: string };
export type MeResponse = { id: number; email: string };
export type TokenResponse = { access_token: string; token_type: "bearer" };

export async function registerUser(payload: RegisterRequest): Promise<MeResponse> {
  return apiPost<RegisterRequest, MeResponse>("/auth/register", payload);
}

export async function loginUser(email: string, password: string): Promise<TokenResponse> {
  const body = new URLSearchParams();
  body.set("username", email);
  body.set("password", password);

  const res = await fetch(
    `${import.meta.env.VITE_API_BASE_URL || "http://127.0.0.1:8000/api/v1"}/auth/login`,
    {
      method: "POST",
      headers: {
        "Content-Type": "application/x-www-form-urlencoded",
        Accept: "application/json",
      },
      body,
    }
  );

  if (!res.ok) {
    const text = await res.text();
    throw new Error(`Login failed: ${res.status} ${text}`);
  }

  return (await res.json()) as TokenResponse;
}

export async function me(token: string): Promise<MeResponse> {
  const res = await fetch(
    `${import.meta.env.VITE_API_BASE_URL || "http://127.0.0.1:8000/api/v1"}/auth/me`,
    {
      method: "GET",
      headers: {
        Accept: "application/json",
        Authorization: `Bearer ${token}`,
      },
    }
  );

  if (!res.ok) {
    const text = await res.text();
    throw new Error(`Me failed: ${res.status} ${text}`);
  }

  return (await res.json()) as MeResponse;
}

export function saveToken(token: string) {
  localStorage.setItem("access_token", token);
}

export function loadToken(): string | null {
  return localStorage.getItem("access_token");
}

export function clearToken() {
  localStorage.removeItem("access_token");
}
