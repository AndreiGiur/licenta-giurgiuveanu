import { useEffect, useState } from "react";
import { motion } from "framer-motion";
import { Link } from "react-router-dom";
import Navbar from "../components/Navbar";
import {
  listAdminUsers, deleteAdminUser, changeAdminUserRole, adminResetPassword,
  listAdminDevices, listAdminScans,
} from "../api/profile";
import type {
  AdminUserRow, AdminDeviceRow, AdminScansPage,
} from "../api/types";


type Tab = "users" | "devices" | "scans";


function formatDate(raw: string): string {
  try {
    return new Date(raw).toLocaleString("ro-RO", {
      day: "2-digit", month: "short", year: "numeric",
      hour: "2-digit", minute: "2-digit",
    });
  } catch { return raw; }
}


// ── Tab: Users ──────────────────────────────────────────────────────────────

function AdminUsersTab() {
  const [users, setUsers] = useState<AdminUserRow[]>([]);
  const [err, setErr] = useState<string | null>(null);
  const [search, setSearch] = useState("");

  async function load() {
    try {
      setUsers(await listAdminUsers());
    } catch (e) {
      setErr(e instanceof Error ? e.message : "Eroare");
    }
  }
  useEffect(() => { load(); }, []);

  async function handleDelete(u: AdminUserRow) {
    if (!window.confirm(`Stergi userul "${u.email}"?\nToate device-urile lui vor fi sterse.`)) return;
    try {
      await deleteAdminUser(u.id);
      await load();
    } catch (e) {
      setErr(e instanceof Error ? e.message : "Eroare la stergere");
    }
  }

  async function handleRoleChange(u: AdminUserRow, role: "user" | "admin") {
    try {
      await changeAdminUserRole(u.id, role);
      await load();
    } catch (e) {
      setErr(e instanceof Error ? e.message : "Eroare la schimbare rol");
    }
  }

  async function handleResetPassword(u: AdminUserRow) {
    const pw = window.prompt(`Parola noua pentru "${u.email}" (min 8 caractere):`);
    if (!pw) return;
    if (pw.length < 8) {
      setErr("Parola trebuie sa aiba minim 8 caractere"); return;
    }
    try {
      await adminResetPassword(u.id, pw);
      window.alert("Parola schimbata. Userul a fost delogat de pe toate sesiunile.");
    } catch (e) {
      setErr(e instanceof Error ? e.message : "Eroare la reset password");
    }
  }

  const filtered = search
    ? users.filter(u => u.email.toLowerCase().includes(search.toLowerCase()))
    : users;

  return (
    <>
      {err && <div className="alert alert-error" style={{ marginBottom: 14 }}>
        <div style={{ fontSize: 12 }}>{err}</div></div>}
      <div style={{ marginBottom: 14, display: "flex", justifyContent: "space-between",
                    alignItems: "center", gap: 12 }}>
        <input
          type="search"
          placeholder="Cauta email..."
          className="profile-input"
          value={search}
          onChange={e => setSearch(e.target.value)}
          style={{ maxWidth: 300 }}
        />
        <span style={{ fontSize: 12, color: "var(--text-muted)" }}>
          {filtered.length} useri
        </span>
      </div>
      <table className="admin-table">
        <thead>
          <tr>
            <th>Email</th>
            <th>Rol</th>
            <th>Provider</th>
            <th>Devices</th>
            <th>Inregistrat</th>
            <th></th>
          </tr>
        </thead>
        <tbody>
          {filtered.map(u => (
            <tr key={u.id}>
              <td>{u.email}</td>
              <td>
                <select className="admin-select" value={u.role}
                        onChange={e => handleRoleChange(u, e.target.value as "user" | "admin")}>
                  <option value="user">user</option>
                  <option value="admin">admin</option>
                </select>
              </td>
              <td><span style={{ fontSize: 11, color: "var(--text-muted)" }}>
                {u.auth_provider}</span></td>
              <td style={{ textAlign: "center" }}>{u.device_count}</td>
              <td><span style={{ fontSize: 11, color: "var(--text-muted)" }}>
                {formatDate(u.created_at)}</span></td>
              <td style={{ textAlign: "right" }}>
                <button className="btn btn-ghost btn-sm"
                        onClick={() => handleResetPassword(u)}
                        title="Reset parola">🔑</button>
                <button className="btn btn-ghost btn-sm"
                        onClick={() => handleDelete(u)}
                        style={{ color: "var(--danger)", marginLeft: 4 }}
                        title="Sterge user">×</button>
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </>
  );
}


// ── Tab: Devices ────────────────────────────────────────────────────────────

function AdminDevicesTab() {
  const [devices, setDevices] = useState<AdminDeviceRow[]>([]);
  useEffect(() => { listAdminDevices().then(setDevices).catch(() => {}); }, []);

  return (
    <table className="admin-table">
      <thead>
        <tr>
          <th>Device UID</th>
          <th>Nume</th>
          <th>Owner</th>
          <th>Status</th>
          <th>Inregistrat</th>
        </tr>
      </thead>
      <tbody>
        {devices.map(d => (
          <tr key={d.id}>
            <td><code style={{ fontSize: 12 }}>{d.device_uid}</code></td>
            <td>{d.name}</td>
            <td><span style={{ fontSize: 12, color: "var(--text-muted)" }}>
              {d.owner_email}</span></td>
            <td>
              <span className={`device-online-badge ${d.is_online ? "online" : "offline"}`}>
                {d.is_online ? "● Online" : "○ Offline"}
              </span>
            </td>
            <td><span style={{ fontSize: 11, color: "var(--text-muted)" }}>
              {formatDate(d.created_at)}</span></td>
          </tr>
        ))}
      </tbody>
    </table>
  );
}


// ── Tab: Scans ──────────────────────────────────────────────────────────────

function AdminScansTab() {
  const [page, setPage] = useState<AdminScansPage | null>(null);
  const [offset, setOffset] = useState(0);
  const LIMIT = 25;

  async function load(o: number) {
    const p = await listAdminScans(LIMIT, o);
    setPage(p);
    setOffset(o);
  }
  useEffect(() => { load(0); }, []);

  if (!page) return <span className="loading-dots"><span /><span /><span /></span>;

  const hasNext = offset + LIMIT < page.total;
  const hasPrev = offset > 0;

  return (
    <>
      <table className="admin-table">
        <thead>
          <tr>
            <th>Scan</th>
            <th>Device</th>
            <th>Owner</th>
            <th>Tip</th>
            <th>Scor</th>
            <th>Data</th>
          </tr>
        </thead>
        <tbody>
          {page.items.map(s => (
            <tr key={s.scan_id}>
              <td><Link to={`/scans/${s.scan_id}`}>#{s.scan_id}</Link></td>
              <td>{s.device_name} <code style={{ fontSize: 11,
                color: "var(--text-muted)" }}>({s.device_uid})</code></td>
              <td><span style={{ fontSize: 12, color: "var(--text-muted)" }}>
                {s.owner_email}</span></td>
              <td><span style={{ fontSize: 11, textTransform: "uppercase",
                color: "var(--accent-strong)" }}>{s.scan_type ?? "?"}</span></td>
              <td style={{ textAlign: "center", fontWeight: 600 }}>{s.exposure_score}/100</td>
              <td><span style={{ fontSize: 11, color: "var(--text-muted)" }}>
                {formatDate(s.created_at)}</span></td>
            </tr>
          ))}
        </tbody>
      </table>
      <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center",
                    marginTop: 16, gap: 12 }}>
        <span style={{ fontSize: 12, color: "var(--text-muted)" }}>
          {offset + 1}-{Math.min(offset + LIMIT, page.total)} din {page.total}
        </span>
        <div style={{ display: "flex", gap: 6 }}>
          <button className="btn btn-ghost btn-sm" disabled={!hasPrev}
                  onClick={() => load(Math.max(0, offset - LIMIT))}>← Anterior</button>
          <button className="btn btn-ghost btn-sm" disabled={!hasNext}
                  onClick={() => load(offset + LIMIT)}>Urmator →</button>
        </div>
      </div>
    </>
  );
}


// ── Pagina principala ──────────────────────────────────────────────────────

export default function Admin() {
  const [tab, setTab] = useState<Tab>("users");

  return (
    <div className="page">
      <Navbar />
      <motion.div className="container"
                  style={{ paddingTop: 32, paddingBottom: 48 }}
                  initial={{ opacity: 0, y: 8 }}
                  animate={{ opacity: 1, y: 0 }}
                  transition={{ duration: 0.4 }}>
        <div className="page-header">
          <h1 className="page-title">
            <span style={{ color: "var(--accent)" }}>⚙</span> Administrare
          </h1>
          <p className="page-subtitle">
            Manage utilizatori, vizualizare toate device-urile si scanarile.
          </p>
        </div>

        <div className="admin-tabs">
          <button className={tab === "users" ? "active" : ""}
                  onClick={() => setTab("users")}>Utilizatori</button>
          <button className={tab === "devices" ? "active" : ""}
                  onClick={() => setTab("devices")}>Dispozitive</button>
          <button className={tab === "scans" ? "active" : ""}
                  onClick={() => setTab("scans")}>Scanari</button>
        </div>

        <div className="admin-content">
          {tab === "users" && <AdminUsersTab />}
          {tab === "devices" && <AdminDevicesTab />}
          {tab === "scans" && <AdminScansTab />}
        </div>
      </motion.div>
    </div>
  );
}
