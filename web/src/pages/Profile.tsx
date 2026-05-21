import { useEffect, useState } from "react";
import { motion } from "framer-motion";
import Navbar from "../components/Navbar";
import { UserAvatar } from "../components/UserAvatar";
import { ScoreTrendChart } from "../components/ScoreTrendChart";
import { fetchMe, updateMyProfile, type Me, type ScanType } from "../api/auth";
import { apiGet } from "../api/http";
import {
  getUserStats, listMySessions, revokeSession, changePassword,
  getPlatformStats,
} from "../api/profile";
import type { UserStats, SessionInfo, PlatformStats, Device } from "../api/types";


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


function displayName(me: Me): string {
  const fn = (me.first_name || "").trim();
  const ln = (me.last_name || "").trim();
  if (fn || ln) return `${fn} ${ln}`.trim();
  return me.email;
}


// ── Sectiune: Cont editabil + parola ──────────────────────────────────────

function AccountSection({ me, onUpdated }: { me: Me; onUpdated: (newMe: Me) => void }) {
  const [editing, setEditing] = useState(false);
  const [firstName, setFirstName] = useState(me.first_name ?? "");
  const [lastName, setLastName] = useState(me.last_name ?? "");
  const [busy, setBusy] = useState(false);
  const [msg, setMsg] = useState<{ kind: "ok" | "err"; text: string } | null>(null);

  // Parola sub-form
  const [showPw, setShowPw] = useState(false);
  const [oldPw, setOldPw] = useState("");
  const [newPw, setNewPw] = useState("");
  const [newPw2, setNewPw2] = useState("");
  const [pwMsg, setPwMsg] = useState<{ kind: "ok" | "err"; text: string } | null>(null);
  const [pwBusy, setPwBusy] = useState(false);

  const hasPassword = me.auth_provider === "password" || me.auth_provider === "both";
  const isAdmin = me.role === "admin";

  async function saveName() {
    setMsg(null);
    setBusy(true);
    try {
      const updated = await updateMyProfile({
        first_name: firstName.trim() || null,
        last_name: lastName.trim() || null,
      });
      onUpdated(updated);
      setMsg({ kind: "ok", text: "Salvat." });
      setEditing(false);
    } catch (e) {
      setMsg({ kind: "err", text: e instanceof Error ? e.message : "Eroare" });
    } finally {
      setBusy(false);
    }
  }

  function cancelEdit() {
    setFirstName(me.first_name ?? "");
    setLastName(me.last_name ?? "");
    setEditing(false);
    setMsg(null);
  }

  async function submitPw() {
    setPwMsg(null);
    if (newPw.length < 8) {
      setPwMsg({ kind: "err", text: "Parola noua trebuie sa aiba minim 8 caractere." });
      return;
    }
    if (newPw !== newPw2) {
      setPwMsg({ kind: "err", text: "Parolele noi nu coincid." });
      return;
    }
    setPwBusy(true);
    try {
      await changePassword(oldPw, newPw);
      setPwMsg({ kind: "ok", text: "Parola schimbata cu succes." });
      setOldPw(""); setNewPw(""); setNewPw2("");
      setShowPw(false);
    } catch (e) {
      setPwMsg({ kind: "err", text: e instanceof Error ? e.message : "Eroare" });
    } finally {
      setPwBusy(false);
    }
  }

  return (
    <section className="profile-section">
      <h2 className="profile-section-title">Cont</h2>

      <div className="profile-account">
        <UserAvatar email={me.email} pictureUrl={me.google_picture_url ?? null} size={64} />
        <div style={{ flex: 1 }}>
          <div className="profile-display-name">{displayName(me)}</div>
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

      {/* Editare nume/prenume */}
      <div className="profile-edit-block">
        {!editing ? (
          <button className="btn btn-ghost btn-sm" onClick={() => setEditing(true)}>
            Editeaza numele
          </button>
        ) : (
          <div className="profile-name-form">
            <div className="profile-name-grid">
              <label className="profile-label">
                <span>Prenume</span>
                <input className="profile-input" type="text" maxLength={64}
                       placeholder="Ex: Maria"
                       value={firstName} onChange={e => setFirstName(e.target.value)} />
              </label>
              <label className="profile-label">
                <span>Nume</span>
                <input className="profile-input" type="text" maxLength={64}
                       placeholder="Ex: Popescu"
                       value={lastName} onChange={e => setLastName(e.target.value)} />
              </label>
            </div>
            <div style={{ display: "flex", gap: 8, marginTop: 8 }}>
              <button className="btn btn-primary btn-sm" onClick={saveName} disabled={busy}>
                Salveaza
              </button>
              <button className="btn btn-ghost btn-sm" onClick={cancelEdit}>Renunta</button>
            </div>
          </div>
        )}
        {msg && (
          <div className="profile-msg" style={{
            color: msg.kind === "ok" ? "var(--success)" : "var(--danger)",
          }}>{msg.text}</div>
        )}
      </div>

      {/* Schimbare parola */}
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
                <button className="btn btn-primary btn-sm" onClick={submitPw} disabled={pwBusy}>
                  Salveaza
                </button>
                <button className="btn btn-ghost btn-sm" onClick={() => {
                  setShowPw(false); setPwMsg(null);
                }}>Renunta</button>
              </div>
            </div>
          )}
          {pwMsg && (
            <div className="profile-msg" style={{
              color: pwMsg.kind === "ok" ? "var(--success)" : "var(--danger)",
            }}>{pwMsg.text}</div>
          )}
        </div>
      )}
    </section>
  );
}


// ── Sectiune: Preferinte ──────────────────────────────────────────────────

function PreferencesSection({ me, onUpdated }: { me: Me; onUpdated: (m: Me) => void }) {
  const [scanType, setScanType] = useState<ScanType>(me.default_scan_type ?? "standard");
  const [busy, setBusy] = useState(false);
  const [msg, setMsg] = useState<{ kind: "ok" | "err"; text: string } | null>(null);

  async function save(newType: ScanType) {
    setScanType(newType);
    setBusy(true);
    setMsg(null);
    try {
      const updated = await updateMyProfile({ default_scan_type: newType });
      onUpdated(updated);
      setMsg({ kind: "ok", text: "Preferinta salvata." });
      setTimeout(() => setMsg(null), 2000);
    } catch (e) {
      setMsg({ kind: "err", text: e instanceof Error ? e.message : "Eroare" });
    } finally {
      setBusy(false);
    }
  }

  return (
    <section className="profile-section">
      <h2 className="profile-section-title">Preferinte</h2>
      <div className="profile-pref-row">
        <div>
          <div className="profile-pref-label">Tip scanare implicit</div>
          <div className="profile-pref-hint">Selectat automat cand declanseaza un scan nou din UI.</div>
        </div>
        <div className="profile-pref-options">
          {(["standard", "advanced", "deep"] as ScanType[]).map(t => (
            <button
              key={t}
              className={`profile-pref-pill ${scanType === t ? "active" : ""}`}
              onClick={() => save(t)}
              disabled={busy}
            >
              {t === "standard" ? "Standard" : t === "advanced" ? "Advanced" : "Deep"}
            </button>
          ))}
        </div>
      </div>
      {msg && (
        <div className="profile-msg" style={{
          color: msg.kind === "ok" ? "var(--success)" : "var(--danger)",
        }}>{msg.text}</div>
      )}
    </section>
  );
}


// ── Sectiune: Statistici + Trend ──────────────────────────────────────────

function StatsSection({
  stats, devices,
}: { stats: UserStats | null; devices: Device[] }) {
  const [trendDeviceUid, setTrendDeviceUid] = useState<string>(devices[0]?.device_uid ?? "");

  useEffect(() => {
    if (!trendDeviceUid && devices.length > 0) {
      setTrendDeviceUid(devices[0].device_uid);
    }
  }, [devices, trendDeviceUid]);

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

      {/* Trend grafic */}
      {devices.length > 0 && (
        <div className="profile-trend-block">
          <div className="profile-trend-header">
            <div>
              <div className="profile-section-subtitle">Evolutie scor (ultimele 30 zile)</div>
              <div className="profile-section-hint">
                Hover pentru a vedea data si tipul scanarii.
              </div>
            </div>
            <select
              className="profile-trend-select"
              value={trendDeviceUid}
              onChange={e => setTrendDeviceUid(e.target.value)}
            >
              {devices.map(d => (
                <option key={d.device_uid} value={d.device_uid}>{d.name}</option>
              ))}
            </select>
          </div>
          {trendDeviceUid && <ScoreTrendChart deviceUid={trendDeviceUid} days={30} height={240} />}
        </div>
      )}
    </section>
  );
}


// ── Sectiune: Sesiuni ─────────────────────────────────────────────────────

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


// ── Sectiune: Platform stats (doar admin) ─────────────────────────────────

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


// ── Pagina principala ─────────────────────────────────────────────────────

export default function Profile() {
  const [me, setMe] = useState<Me | null>(null);
  const [stats, setStats] = useState<UserStats | null>(null);
  const [sessions, setSessions] = useState<SessionInfo[]>([]);
  const [platformStats, setPlatformStats] = useState<PlatformStats | null>(null);
  const [devices, setDevices] = useState<Device[]>([]);

  async function loadAll() {
    const meData = await fetchMe();
    setMe(meData);
    const [statsData, sessionsData, devicesData] = await Promise.all([
      getUserStats(),
      listMySessions(),
      apiGet<Device[]>("/devices"),
    ]);
    setStats(statsData);
    setSessions(sessionsData);
    setDevices(devicesData);
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
                  style={{ paddingTop: 32, paddingBottom: 48, maxWidth: 920 }}
                  initial={{ opacity: 0, y: 8 }}
                  animate={{ opacity: 1, y: 0 }}
                  transition={{ duration: 0.4 }}>
        <div className="page-header">
          <h1 className="page-title">Profil</h1>
          <p className="page-subtitle">
            {me.role === "admin"
              ? "Cont administrator — gestionezi conturile + vezi platforma globala."
              : "Datele contului tau, preferinte si statistici personale."}
          </p>
        </div>

        <AccountSection me={me} onUpdated={setMe} />
        <PreferencesSection me={me} onUpdated={setMe} />
        <StatsSection stats={stats} devices={devices} />
        <SessionsSection sessions={sessions} onRevoked={loadAll} />
        {me.role === "admin" && <PlatformSection stats={platformStats} />}
      </motion.div>
    </div>
  );
}
