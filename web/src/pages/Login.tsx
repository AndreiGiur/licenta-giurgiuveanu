import { useState } from "react";
import { loginUser, saveToken } from "../api/auth";
import { useNavigate } from "react-router-dom";

function isValidEmail(email: string) {
  return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email);
}

export default function Login() {
  const nav = useNavigate();

  const [email, setEmail] = useState("test@example.com");
  const [password, setPassword] = useState("Password123!");
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  async function onSubmit(e: React.FormEvent) {
    e.preventDefault();
    setError(null);

    const e1 = email.trim().toLowerCase();
    if (!isValidEmail(e1)) {
      setError("Email invalid");
      return;
    }

    setLoading(true);
    try {
      const tok = await loginUser(e1, password);
      saveToken(tok.access_token);
      nav("/dashboard");
    } catch (err) {
      setError(err instanceof Error ? err.message : "Eroare");
    } finally {
      setLoading(false);
    }
  }

  return (
    <div
      style={{
        minHeight: "100vh",
        background: "#0b0b0b",
        color: "#e5e5e5",
        fontFamily: "system-ui, -apple-system, Segoe UI, Roboto, Arial, sans-serif",
        display: "grid",
        placeItems: "center",
        padding: 16,
      }}
    >
      <div style={{ width: "100%", maxWidth: 420 }}>
        <h1 style={{ margin: 0, fontSize: 24, fontWeight: 900 }}>Login</h1>

        <form
          onSubmit={onSubmit}
          style={{
            marginTop: 16,
            border: "1px solid #2a2a2a",
            borderRadius: 14,
            padding: 16,
            background: "#0f0f0f",
          }}
        >
          <label style={{ display: "block", fontSize: 12, opacity: 0.8, marginBottom: 6 }}>
            Email
          </label>
          <input
            value={email}
            onChange={(e) => setEmail(e.target.value)}
            autoComplete="email"
            style={{
              width: "100%",
              height: 40,
              padding: "0 2px",
              borderRadius: 10,
              border: "1px solid #2a2a2a",
              background: "#0b0b0b",
              color: "#e5e5e5",
              outline: "none",
              marginBottom: 12,
            }}
          />

          <label style={{ display: "block", fontSize: 12, opacity: 0.8, marginBottom: 6 }}>
            Password
          </label>
          <input
            value={password}
            onChange={(e) => setPassword(e.target.value)}
            type="password"
            autoComplete="current-password"
            style={{
              width: "100%",
              height: 40,
              padding: "0 2px",
              borderRadius: 10,
              border: "1px solid #2a2a2a",
              background: "#0b0b0b",
              color: "#e5e5e5",
              outline: "none",
              marginBottom: 12,
            }}
          />

          {error && (
            <div
              style={{
                border: "1px solid #7f1d1d",
                background: "#160b0b",
                borderRadius: 12,
                padding: 12,
                fontSize: 13,
                whiteSpace: "pre-wrap",
                marginBottom: 12,
              }}
            >
              {error}
            </div>
          )}

          <button
            type="submit"
            disabled={loading}
            style={{
              width: "100%",
              height: 42,
              borderRadius: 12,
              border: "1px solid #2a2a2a",
              background: "#111",
              color: "#e5e5e5",
              fontWeight: 900,
              cursor: loading ? "not-allowed" : "pointer",
            }}
          >
            {loading ? "Working..." : "Login"}
          </button>

          <button
            type="button"
            onClick={() => nav("/register")}
            style={{
              width: "100%",
              height: 42,
              marginTop: 10,
              borderRadius: 12,
              border: "1px solid #2a2a2a",
              background: "transparent",
              color: "#e5e5e5",
              fontWeight: 800,
              cursor: "pointer",
              opacity: 0.9,
            }}
          >
            Create account
          </button>
        </form>
      </div>
    </div>
  );
}
