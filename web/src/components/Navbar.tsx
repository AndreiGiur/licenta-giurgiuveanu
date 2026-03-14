import { useEffect, useState } from "react";
import { useNavigate, useLocation } from "react-router-dom";
import { fetchMe, logoutUser } from "../api/auth";

const ShieldIcon = () => (
  <svg width="15" height="15" viewBox="0 0 24 24" fill="none"
    stroke="#021018" strokeWidth="2.5" strokeLinecap="round" strokeLinejoin="round">
    <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z" />
  </svg>
);

export default function Navbar() {
  const navigate = useNavigate();
  const location = useLocation();
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
    } catch {
      navigate("/login", { replace: true });
    }
  }

  const isActive = (path: string) => location.pathname === path;

  return (
    <nav className="navbar">
      <div className="navbar-inner">
        {/* Left: brand + nav links */}
        <div style={{ display: "flex", alignItems: "center" }}>
          <div className="navbar-brand" onClick={() => navigate("/dashboard")}>
            <div className="navbar-brand-icon">
              <ShieldIcon />
            </div>
            <span className="navbar-brand-name">VulnWatch</span>
          </div>

          <div className="navbar-nav">
            <button
              onClick={() => navigate("/dashboard")}
              className={`nav-link ${isActive("/dashboard") ? "active" : ""}`}
            >
              Dashboard
            </button>
            <button
              onClick={() => navigate("/devices")}
              className={`nav-link ${isActive("/devices") ? "active" : ""}`}
            >
              Devices
            </button>
          </div>
        </div>

        {/* Right: user badge + logout */}
        <div className="navbar-right">
          {email && (
            <div className="user-badge">
              <span className="user-dot" />
              <span style={{ overflow: "hidden", textOverflow: "ellipsis" }}>{email}</span>
            </div>
          )}
          <button
            onClick={handleLogout}
            disabled={loggingOut}
            className="btn btn-danger btn-sm"
          >
            {loggingOut ? "..." : "Logout"}
          </button>
        </div>
      </div>
    </nav>
  );
}
