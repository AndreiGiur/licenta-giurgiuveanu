import { useState, useEffect } from "react";
import { useNavigate } from "react-router-dom";
import { registerUser, loginUser, saveSessionToken, getSessionToken } from "../api/auth";

function isValidEmail(email: string): boolean {
  return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email);
}

export default function Register() {
  const navigate = useNavigate();

  useEffect(() => {
    if (getSessionToken()) {
      navigate("/dashboard", { replace: true });
    }
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
      setError("Email invalid");
      return;
    }
    if (normalizedPassword.length < 8) {
      setError("Parola prea scurta (minim 8)");
      return;
    }

    setLoading(true);
    try {
      await registerUser({ email: normalizedEmail, password: normalizedPassword });
      const tok = await loginUser({ email: normalizedEmail, password: normalizedPassword });
      saveSessionToken(tok.session_token);
      navigate("/dashboard");
    } catch (err: any) {
      setError(err?.message ?? "Eroare");
    } finally {
      setLoading(false);
    }
  }

  return (
    <div style={{ minHeight: "100vh", background: "#0b0b0b", color: "#e5e5e5", display: "grid", placeItems: "center", padding: 16 }}>
      <div style={{ width: "100%", maxWidth: 420 }}>
        <h1 style={{ margin: 0, fontSize: 24, fontWeight: 900 }}>Register</h1>

        <form onSubmit={onSubmit} style={{ marginTop: 16, border: "1px solid #2a2a2a", borderRadius: 14, padding: 16, background: "#0f0f0f" }}>
          <label style={{ display: "block", fontSize: 12, opacity: 0.8, marginBottom: 6 }}>Email</label>
          <input
            value={email}
            onChange={(e) => setEmail(e.target.value)}
            autoComplete="email"
            style={{ width: "100%", height: 40, padding: "0 12px", borderRadius: 10, border: "1px solid #2a2a2a", background: "#0b0b0b", color: "#e5e5e5", outline: "none", marginBottom: 12 }}
          />

          <label style={{ display: "block", fontSize: 12, opacity: 0.8, marginBottom: 6 }}>Password</label>
          <input
            type="password"
            value={password}
            onChange={(e) => setPassword(e.target.value)}
            autoComplete="new-password"
            style={{ width: "100%", height: 40, padding: "0 12px", borderRadius: 10, border: "1px solid #2a2a2a", background: "#0b0b0b", color: "#e5e5e5", outline: "none", marginBottom: 12 }}
          />

          {error && (
            <div style={{ border: "1px solid #7f1d1d", background: "#160b0b", borderRadius: 12, padding: 12, fontSize: 13, marginBottom: 12, whiteSpace: "pre-wrap" }}>
              {error}
            </div>
          )}

          <button
            type="submit"
            disabled={loading}
            style={{ width: "100%", height: 42, borderRadius: 12, border: "1px solid #2a2a2a", background: "#111", color: "#e5e5e5", fontWeight: 900, cursor: loading ? "not-allowed" : "pointer" }}
          >
            {loading ? "Working..." : "Register"}
          </button>

          <button
            type="button"
            onClick={() => navigate("/login")}
            style={{ width: "100%", height: 42, marginTop: 10, borderRadius: 12, border: "1px solid #2a2a2a", background: "transparent", color: "#e5e5e5", fontWeight: 800, cursor: "pointer", opacity: 0.9 }}
          >
            Go to login
          </button>
        </form>
      </div>
    </div>
  );
}
