import { useEffect, useState } from "react";
import { useNavigate } from "react-router-dom";
import { fetchMe } from "../api/auth";

/**
 * Garda de routing: incearca /auth/me cu cookie-ul HttpOnly. Daca esueaza,
 * redirectioneaza la /login. Nu citeste niciun token din JS — sursa de adevar
 * este cookie-ul gestionat de server.
 */
export default function ProtectedRoute({ children }: { children: React.ReactNode }) {
  const navigate = useNavigate();
  const [checking, setChecking] = useState(true);

  useEffect(() => {
    let cancelled = false;
    fetchMe()
      .then(() => { if (!cancelled) setChecking(false); })
      .catch(() => { if (!cancelled) navigate("/login", { replace: true }); });
    return () => { cancelled = true; };
  }, [navigate]);

  if (checking) {
    return (
      <div style={{ minHeight: "100vh", display: "grid", placeItems: "center" }}>
        <div>Verificare sesiune...</div>
      </div>
    );
  }

  return <>{children}</>;
}
