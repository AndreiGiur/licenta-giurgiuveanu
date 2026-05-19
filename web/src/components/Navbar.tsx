import { useEffect, useState } from "react";
import { useNavigate, useLocation } from "react-router-dom";
import { fetchMe, logoutUser, type Me } from "../api/auth";
import { ThemeToggle } from "./ThemeToggle";
import { UserAvatar } from "./UserAvatar";

export default function Navbar() {
  const navigate = useNavigate();
  const location = useLocation();
  const [me, setMe] = useState<Me | null>(null);
  const [loggingOut, setLoggingOut] = useState(false);

  useEffect(() => {
    let cancel = false;
    fetchMe()
      .then((user) => { if (!cancel) setMe(user); })
      .catch(() => { if (!cancel) setMe(null); });
    return () => { cancel = true; };
  }, [location.pathname]);

  async function handleLogout() {
    setLoggingOut(true);
    try {
      await logoutUser();
      navigate("/login", { replace: true });
    } catch {
      navigate("/login", { replace: true });
    }
  }

  const isActive = (path: string) =>
    location.pathname === path || location.pathname.startsWith(path + "/");

  return (
    <nav className="navbar">
      <div className="navbar-inner">
        <div
          className="navbar-brand"
          onClick={() => navigate("/dashboard")}
          style={{ cursor: "pointer" }}
        >
          <span className="navbar-brand-mark">●</span>
          <span className="navbar-brand-text">VulnWatch</span>
        </div>

        <div className="navbar-links">
          <button
            onClick={() => navigate("/dashboard")}
            className={`navbar-link ${isActive("/dashboard") ? "active" : ""}`}
          >
            Dashboard
          </button>
          <button
            onClick={() => navigate("/devices")}
            className={`navbar-link ${isActive("/devices") ? "active" : ""}`}
          >
            Dispozitive
          </button>
          <button
            onClick={() => navigate("/profile")}
            className={`navbar-link ${isActive("/profile") ? "active" : ""}`}
          >
            Profil
          </button>
        </div>

        <div className="navbar-actions">
          {me?.role === "admin" && (
            <button
              onClick={() => navigate("/admin")}
              className={`navbar-admin-link ${isActive("/admin") ? "active" : ""}`}
              title="Administrare platforma"
            >
              ⚙ Admin
            </button>
          )}
          <ThemeToggle />
          {me && (
            <>
              <UserAvatar
                email={me.email}
                pictureUrl={me.google_picture_url ?? undefined}
                size={32}
              />
              <button
                onClick={handleLogout}
                disabled={loggingOut}
                className="btn btn-ghost btn-sm"
                style={{ border: "1px solid var(--border)" }}
              >
                {loggingOut ? "..." : "Logout"}
              </button>
            </>
          )}
        </div>
      </div>
    </nav>
  );
}
