import { useEffect, useState } from "react";
import { useNavigate } from "react-router-dom";
import { fetchMe, logoutUser } from "../api/auth";

export default function Navbar() {
  const navigate = useNavigate();
  const [email, setEmail] = useState<string | null>(null);
  const [loggingOut, setLoggingOut] = useState(false);

  useEffect(() => {
    fetchMe()
      .then((user) => setEmail(user.email))
      .catch(() => setEmail(null));
  }, []);

  async function handleLogout() {
    setLoggingOut(true);
    try {
      await logoutUser();
      navigate("/login", { replace: true });
    } catch (e) {
      console.error("Logout failed:", e);
      navigate("/login", { replace: true });
    }
  }

  return (
    <div
      style={{
        borderBottom: "1px solid #e5e5e5",
        background: "#fafafa",
        padding: "12px 20px",
      }}
    >
      <div
        style={{
          maxWidth: 1100,
          margin: "0 auto",
          display: "flex",
          justifyContent: "space-between",
          alignItems: "center",
        }}
      >
        <div style={{ display: "flex", gap: 24, alignItems: "center" }}>
          <div style={{ fontWeight: 900, fontSize: 16 }}>Exposure Platform</div>
          <button
            onClick={() => navigate("/dashboard")}
            style={{
              background: "transparent",
              border: "none",
              fontWeight: 600,
              cursor: "pointer",
              fontSize: 14,
              padding: "6px 12px",
            }}
          >
            Dashboard
          </button>
          <button
            onClick={() => navigate("/devices")}
            style={{
              background: "transparent",
              border: "none",
              fontWeight: 600,
              cursor: "pointer",
              fontSize: 14,
              padding: "6px 12px",
            }}
          >
            Devices
          </button>
        </div>

        <div style={{ display: "flex", gap: 16, alignItems: "center" }}>
          {email && (
            <div style={{ fontSize: 13, opacity: 0.7 }}>{email}</div>
          )}
          <button
            onClick={handleLogout}
            disabled={loggingOut}
            style={{
              background: "#0f0f0f",
              color: "white",
              border: "none",
              borderRadius: 8,
              padding: "6px 16px",
              fontWeight: 700,
              cursor: loggingOut ? "not-allowed" : "pointer",
              fontSize: 13,
              opacity: loggingOut ? 0.5 : 1,
            }}
          >
            {loggingOut ? "..." : "Logout"}
          </button>
        </div>
      </div>
    </div>
  );
}
