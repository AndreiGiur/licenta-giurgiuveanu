import { useEffect, useState } from "react";
import { useNavigate } from "react-router-dom";
import { fetchMe } from "../api/auth";

/**
 * Garda de routing: incearca /auth/me cu cookie-ul HttpOnly. Daca esueaza,
 * redirectioneaza la /login. Nu citeste niciun token din JS — sursa de adevar
 * este cookie-ul gestionat de server.
 *
 * `requireAdmin`: daca true, redirect-eaza la /dashboard daca user-ul nu e admin.
 */
interface Props {
  children: React.ReactNode;
  requireAdmin?: boolean;
}

export default function ProtectedRoute({ children, requireAdmin }: Props) {
  const navigate = useNavigate();
  const [checking, setChecking] = useState(true);

  useEffect(() => {
    let cancelled = false;
    fetchMe()
      .then((me) => {
        if (cancelled) return;
        if (requireAdmin && me.role !== "admin") {
          navigate("/dashboard", { replace: true });
          return;
        }
        setChecking(false);
      })
      .catch(() => { if (!cancelled) navigate("/login", { replace: true }); });
    return () => { cancelled = true; };
  }, [navigate, requireAdmin]);

  if (checking) {
    return (
      <div style={{ minHeight: "100vh", display: "grid", placeItems: "center" }}>
        <div>Verificare sesiune...</div>
      </div>
    );
  }

  return <>{children}</>;
}
