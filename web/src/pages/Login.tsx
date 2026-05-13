import { useState, useEffect, type FormEvent } from "react";
import { Link, useNavigate } from "react-router-dom";
import { motion } from "framer-motion";
import { loginUser, fetchMe } from "../api/auth";
import { GoogleButton } from "../components/GoogleButton";

function isValidEmail(email: string): boolean {
  return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email);
}

export default function Login() {
  const navigate = useNavigate();
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  // Daca user-ul are deja sesiune valida (cookie HttpOnly), il redirectam.
  useEffect(() => {
    let cancelled = false;
    fetchMe()
      .then(() => { if (!cancelled) navigate("/dashboard", { replace: true }); })
      .catch(() => { /* nu e logat — ramane pe pagina */ });
    return () => { cancelled = true; };
  }, [navigate]);

  async function handleSubmit(e: FormEvent) {
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
    } catch (err) {
      setError(err instanceof Error ? err.message : "Eroare la autentificare");
    } finally {
      setLoading(false);
    }
  }

  return (
    <div className="auth-page">
      <motion.div
        className="auth-card"
        initial={{ opacity: 0, y: 12 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ duration: 0.4, ease: [0.16, 1, 0.3, 1] }}
      >
        <div className="auth-header">
          <h1 className="auth-title">Bine ai revenit</h1>
          <p className="auth-subtitle">Conectează-te la VulnWatch</p>
        </div>

        <GoogleButton onError={setError} />

        <div className="auth-divider">
          <span>sau</span>
        </div>

        <form onSubmit={handleSubmit} className="auth-form">
          <div className="form-group">
            <label className="form-label">Email</label>
            <input
              className="form-input"
              type="email"
              value={email}
              onChange={(e) => setEmail(e.target.value)}
              placeholder="nume@exemplu.com"
              autoComplete="email"
              required
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
              required
            />
          </div>

          {error && <div className="auth-error">{error}</div>}

          <button type="submit" disabled={loading} className="btn btn-primary auth-submit">
            {loading ? (
              <span className="loading-dots"><span /><span /><span /></span>
            ) : "Autentifică-te"}
          </button>
        </form>

        <p className="auth-switch">
          Nu ai cont? <Link to="/register" className="auth-link">Înregistrează-te</Link>
        </p>
      </motion.div>
    </div>
  );
}
