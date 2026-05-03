import { useState, useEffect } from "react";
import { useNavigate } from "react-router-dom";
import { loginUser, fetchMe } from "../api/auth";

const ShieldIcon = () => (
  <svg width="18" height="18" viewBox="0 0 24 24" fill="none"
    stroke="#021018" strokeWidth="2.5" strokeLinecap="round" strokeLinejoin="round">
    <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z" />
  </svg>
);

function isValidEmail(email: string): boolean {
  return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email);
}

export default function Login() {
  const navigate = useNavigate();

  // Daca user-ul are deja sesiune valida (cookie HttpOnly), il redirectam.
  useEffect(() => {
    let cancelled = false;
    fetchMe()
      .then(() => { if (!cancelled) navigate("/dashboard", { replace: true }); })
      .catch(() => { /* nu e logat — ramane pe pagina */ });
    return () => { cancelled = true; };
  }, [navigate]);

  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  async function onSubmit(e: React.FormEvent) {
    e.preventDefault();
    setError(null);
    const normalizedEmail = email.trim().toLowerCase();
    const normalizedPassword = password.trim();
    if (!isValidEmail(normalizedEmail)) {
      setError("Adresă de email invalidă.");
      return;
    }
    setLoading(true);
    try {
      await loginUser({ email: normalizedEmail, password: normalizedPassword });
      navigate("/dashboard");
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : "Eroare la autentificare";
      setError(msg);
    } finally {
      setLoading(false);
    }
  }

  return (
    <div className="auth-page">
      <div className="auth-card">
        {/* Brand */}
        <div className="auth-brand">
          <div className="auth-brand-icon"><ShieldIcon /></div>
          <span className="auth-brand-name">VulnWatch</span>
        </div>

        <h1 className="auth-title">Bine ai revenit</h1>
        <p className="auth-subtitle">Autentifică-te pentru a accesa platforma</p>

        <form onSubmit={onSubmit}>
          <div className="form-group">
            <label className="form-label">Email</label>
            <input
              className="form-input"
              type="email"
              value={email}
              onChange={(e) => setEmail(e.target.value)}
              placeholder="nume@exemplu.com"
              autoComplete="email"
            />
          </div>

          <div className="form-group">
            <label className="form-label">Parolă</label>
            <input
              className="form-input"
              type="password"
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              placeholder="••••••••"
              autoComplete="current-password"
            />
          </div>

          {error && (
            <div className="alert alert-error" style={{ marginBottom: 16 }}>
              {error}
            </div>
          )}

          <button type="submit" disabled={loading} className="btn btn-primary">
            {loading ? (
              <span className="loading-dots"><span /><span /><span /></span>
            ) : "Autentificare"}
          </button>
          <button
            type="button"
            onClick={() => navigate("/register")}
            className="btn btn-secondary"
          >
            Nu ai cont? <strong>Înregistrează-te</strong>
          </button>
        </form>
      </div>
    </div>
  );
}
