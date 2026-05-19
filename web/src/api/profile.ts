import { apiGet, apiPost, apiDelete } from "./client";
import type {
  UserStats, SessionInfo, PlatformStats,
  AdminUserRow, AdminDeviceRow, AdminScansPage,
} from "./types";

// ── User profile ────────────────────────────────────────────────────────────

export function getUserStats() {
  return apiGet<UserStats>("/me/stats");
}

export function listMySessions() {
  return apiGet<SessionInfo[]>("/me/sessions");
}

export function revokeSession(sessionId: number) {
  return apiDelete(`/me/sessions/${sessionId}`);
}

export function changePassword(oldPassword: string, newPassword: string) {
  return apiPost<{ old_password: string; new_password: string }, { ok: boolean }>(
    "/me/password",
    { old_password: oldPassword, new_password: newPassword },
  );
}

// ── Admin ────────────────────────────────────────────────────────────────────

export function getPlatformStats() {
  return apiGet<PlatformStats>("/admin/stats");
}

export function listAdminUsers() {
  return apiGet<AdminUserRow[]>("/admin/users");
}

export function deleteAdminUser(userId: number) {
  return apiDelete(`/admin/users/${userId}`);
}

export function changeAdminUserRole(userId: number, role: "user" | "admin") {
  return apiPost<{ role: string }, AdminUserRow>(
    `/admin/users/${userId}/role`,
    { role },
  );
}

export function adminResetPassword(userId: number, newPassword: string) {
  return apiPost<{ new_password: string }, { ok: boolean }>(
    `/admin/users/${userId}/reset-password`,
    { new_password: newPassword },
  );
}

export function listAdminDevices() {
  return apiGet<AdminDeviceRow[]>("/admin/devices");
}

export function listAdminScans(limit = 50, offset = 0) {
  return apiGet<AdminScansPage>(`/admin/scans?limit=${limit}&offset=${offset}`);
}
