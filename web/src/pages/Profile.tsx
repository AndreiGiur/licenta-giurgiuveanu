import { useEffect, useState } from "react";
import { motion } from "framer-motion";
import Navbar from "../components/Navbar";
import UserAvatar from "../components/UserAvatar";
import { fetchMe, type Me } from "../api/auth";
import {
  getUserStats, listMySessions, revokeSession, changePassword,
  getPlatformStats,
} from "../api/profile";
import type { UserStats, SessionInfo, PlatformStats } from "../api/types";


function formatDate(raw: string | null): string {
  if (!raw) return "—";
  try {
    return new Date(raw).toLocaleString("ro-RO", {
      day: "2-digit", month: "short", year: "numeric",
      hour: "2-digit", minute: "2-digit",
    });
  } catch { return raw; }
}


function truncateUA(ua: string | null): string {
  if (!ua) return "—";
  if (ua.length <= 60) return ua;
  return ua.slice(0, 57) + "...";
}


// ── Sectiune: Cont ──────────────────────────────────────────────────────────

function AccountSection({ me }: { me: Me }) {
  const [showPw, setShowPw] = useState(false);
  const [oldPw, setOldPw] = useState("");
  const [newPw, setNewPw] = useState("");
  const [newPw2, setNewPw2] = useState("");
  const [msg, setMsg] = useState<{ kind: "ok" | "err"; text: string } | null>(null);
  const [busy, setBusy] = useState(false);

  const hasPassword = me.auth_provider === "password" || me.auth_provider === "both";
  const isAdmin = me.role === "admin";

  async function submitPw() {
    setMsg(null);
    if (newPw.length < 8) {
      setMsg({ kind: "err", text: "Parola noua trebuie sa aiba minim 8 caractere." });
      return;
    }
    if (newPw !== newPw2) {
      setMsg({ kind: "err", text: "Parolele noi nu coincid." });
      return;
    }
    setBusy(true);
    try {
      await changePassword(oldPw, newPw);
      setMsg({ kind: "ok", text: "Parola schimbata cu succes." });
      setOldPw(""); setNewPw(""); setNewPw2("");
      setShowPw(false);
    } catch (e) {
      setMsg({ kind: "err", text: e instanceof Error ? e.message : "Eroare" });
    } finally {
      setBusy(false);
    }
  }

  return (
    <section className="profile-section">
      <h2 className="profile-section-title">Cont</h2>
      <div className="profile-account">
        <UserAvatar email={me.email} pictureUrl={me.google_picture_url ?? null} size={64} />
        <div style={{ flex: 1 }}>
          <div className="profile-email">{me.email}</div>
          <div className="profile-meta">
            <span className="profile-tag">
              {me.auth_provider === "google" ? "Google"
                : me.auth_provider === "both" ? "Email + Google"
                : "Email & parola"}
            </span>
            {isAdmin && <span className="profile-tag profile-tag-admin">ADMIN</span>}
          </div>
        </div>
      </div>

      {hasPassword && (
        <div className="profile-password">
          {!showPw ? (
            <button className="btn btn-ghost btn-sm" onClick={() => setShowPw(true)}>
              Schimba parola
            </button>
          ) : (
            <div className="profile-pw-form">
              <input className="profile-input" type="password" placeholder="Parola actuala"
                     value={oldPw} onChange={e => setOldPw(e.target.value)} />
              <input className="profile-input" type="password" placeholder="Parola noua"
                     value={newPw} onChange={e => setNewPw(e.target.value)} />
              <input className="profile-input" type="password" placeholder="Confirmare parola noua"
                     value={newPw2} onChange={e => setNewPw2(e.target.value)} />
              <div style={{ display: "flex", gap: 8 }}>
                <button className="btn btn-primary btn-sm" onClick={submitPw} disabled={busy}>
                  Salveaza
                </button>
                <button className="btn btn-ghost btn-sm" onClick={() => {
                  setShowPw(false); setMsg(null);
                }}>Renunta</button>
              </div>
            </div>
          )}
          {msg && (
            <div style={{
              marginTop: 8, fontSize: 12,
              color: msg.kind === "ok" ? "var(--success)" : "var(--danger)",
            }}>{msg.text}</div>
          )}
        </div>
      )}
    </section>
  );
}


// ── Sectiune: Statistici ────────────────────────────────────────────────────

function StatsSection({ stats }: { stats: UserStats | null }) {
  if (!stats) return null;
  return (
    <section className="profile-section">
      <h2 className="profile-section-title">Statistici personale</h2>
      <div className="profile-stats-grid">
        <div className="profile-stat-card">
          <div className="profile-stat-label">Device-uri</div>
          <div className="profile-stat-value">{stats.device_count}</div>
        </div>
        <div className="profile-stat-card">
          <div className="profile-stat-label">Total scanari</div>
          <div className="profile-stat-value">{stats.scan_count}</div>
        </div>
        <div className="profile-stat-card">
          <div className="profile-stat-label">Scor mediu</div>
          <div className="profile-stat-value">
            {stats.avg_exposure_score !== null
              ? `${stats.avg_exposure_score}/100` : "—"}
          </div>
        </div>
        <div className="profile-stat-card">
          <div className="profile-stat-label">Ultima scanare</div>
          <div className="profile-stat-value-small">
            {formatDate(stats.last_scan_at)}
          </div>
          {stats.last_scan_score !== null && (
            <div className="profile-stat-sub">Scor: {stats.last_scan_score}/100</div>
          )}
        </div>
      </div>
    </section>
  );
}


// ── Sectiune: Sesiuni ───────────────────────────────────────────────────────

function SessionsSection({ sessions, onRevoked }:
    { sessions: SessionInfo[]; onRevoked: () => void }) {
  async function handleRevoke(id: number) {
    if (!window.confirm("Revoci aceasta sesiune?")) return;
    await revokeSession(id);
    onRevoked();
  }
  return (
    <section className="profile-section">
      <h2 className="profile-section-title">Sesiuni active</h2>
      <div className="profile-sessions">
        {sessions.map(s => (
          <div key={s.id} className="profile-session-row">
            <div style={{ flex: 1, minWidth: 0 }}>
              <div className="profile-session-ua">
                {truncateUA(s.user_agent)}
                {s.is_current && <span className="profile-tag profile-tag-current">ACEASTA</span>}
              </div>
              <div className="profile-session-meta">
                IP: {s.ip ?? "?"} · creat: {formatDate(s.created_at)}
              </div>
            </div>
            {!s.is_current && (
              <button className="btn btn-ghost btn-sm" onClick={() => handleRevoke(s.id)}>
                Revoca
              </button>
            )}
          </div>
        ))}
      </div>
    </section>
  );
}


// ── Sectiune: Platform stats (doar admin) ───────────────────────────────────

function PlatformSection({ stats }: { stats: PlatformStats | null }) {
  if (!stats) return null;
  return (
    <section className="profile-section profile-section-admin">
      <h2 className="profile-section-title">
        <span style={{ color: "var(--accent)" }}>⚙</span> Platforma
      </h2>
      <div className="profile-stats-grid">
        <div className="profile-stat-card">
          <div className="profile-stat-label">Total useri</div>
          <div className="profile-stat-value">{stats.total_users}</div>
        </div>
        <div className="profile-stat-card">
          <div className="profile-stat-label">Devices online</div>
          <div className="profile-stat-value">
            {stats.devices_online}<span style={{ fontSize: 14, color: "var(--text-muted)" }}>
              /{stats.total_devices}</span>
          </div>
        </div>
        <div className="profile-stat-card">
          <div className="profile-stat-label">Scanari ultimele 24h</div>
          <div className="profile-stat-value">{stats.scans_last_24h}</div>
        </div>
        <div className="profile-stat-card">
          <div className="profile-stat-label">Scor mediu platforma</div>
          <div className="profile-stat-value">
            {stats.avg_exposure_score !== null
              ? `${stats.avg_exposure_score}/100` : "—"}
          </div>
        </div>
      </div>
    </section>
  );
}


// ── Pagina principala ──────────────────────────────────────────────────────

export default function Profile() {
  const [me, setMe] = useState<Me | null>(null);
  const [stats, setStats] = useState<UserStats | null>(null);
  const [sessions, setSessions] = useState<SessionInfo[]>([]);
  const [platformStats, setPlatformStats] = useState<PlatformStats | null>(null);

  async function loadAll() {
    const meData = await fetchMe();
    setMe(meData);
    const [statsData, sessionsData] = await Promise.all([
      getUserStats(), listMySessions(),
    ]);
    setStats(statsData);
    setSessions(sessionsData);
    if (meData.role === "admin") {
      try {
        const ps = await getPlatformStats();
        setPlatformStats(ps);
      } catch {
        // ignore
      }
    }
  }

  useEffect(() => { loadAll(); }, []);

  if (!me) {
    return (
      <div className="page">
        <Navbar />
        <div className="container" style={{ paddingTop: 32 }}>
          <span className="loading-dots"><span /><span /><span /></span>
        </div>
      </div>
    );
  }

  return (
    <div className="page">
      <Navbar />
      <motion.div className="container"
                  style={{ paddingTop: 32, paddingBottom: 48, maxWidth: 900 }}
                  initial={{ opacity: 0, y: 8 }}
                  animate={{ opacity: 1, y: 0 }}
                  transition={{ duration: 0.4 }}>
        <div className="page-header">
          <h1 className="page-title">Profil</h1>
          <p className="page-subtitle">
            {me.role === "admin"
              ? "Cont administrator — gestionezi conturile + vezi platforma globala."
              : "Datele contului tau si setarile platformei."}
          </p>
        </div>

        <AccountSection me={me} />
        <StatsSection stats={stats} />
        <SessionsSection sessions={sessions} onRevoked={loadAll} />
        {me.role === "admin" && <PlatformSection stats={platformStats} />}
      </motion.div>
    </div>
  );
}
