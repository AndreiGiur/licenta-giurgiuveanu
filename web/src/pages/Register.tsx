import { useState, useEffect, type FormEvent } from "react";
import { Link, useNavigate } from "react-router-dom";
import { motion } from "framer-motion";
import { registerUser, loginUser, fetchMe } from "../api/auth";
import { GoogleButton } from "../components/GoogleButton";

function isValidEmail(email: string): boolean {
  return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email);
}

export default function Register() {
  const navigate = useNavigate();
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

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
    if (normalizedPassword.length < 8) {
      setError("Parola trebuie să aibă cel puțin 8 caractere.");
      return;
    }
    setLoading(true);
    try {
      await registerUser({ email: normalizedEmail, password: normalizedPassword });
      await loginUser({ email: normalizedEmail, password: normalizedPassword });
      navigate("/dashboard");
    } catch (err) {
      setError(err instanceof Error ? err.message : "Eroare la înregistrare");
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
          <h1 className="auth-title">Bun venit la VulnWatch</h1>
          <p className="auth-subtitle">Creează un cont nou</p>
        </div>

        <GoogleButton label="Înregistrează-te cu Google" onError={setError} />

        <div className="auth-divider"><span>sau</span></div>

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
            <label className="form-label">Parolă (min. 8 caractere)</label>
            <input
              className="form-input"
              type="password"
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              placeholder="••••••••"
              autoComplete="new-password"
              required
              minLength={8}
            />
          </div>

          {error && <div className="auth-error">{error}</div>}

          <button type="submit" disabled={loading} className="btn btn-primary auth-submit">
            {loading ? (
              <span className="loading-dots"><span /><span /><span /></span>
            ) : "Creează contul"}
          </button>
        </form>

        <p className="auth-switch">
          Ai deja cont? <Link to="/login" className="auth-link">Autentifică-te</Link>
        </p>
      </motion.div>
    </div>
  );
}
