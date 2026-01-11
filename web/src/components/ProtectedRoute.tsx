import { useEffect, useState } from "react";
import { useNavigate } from "react-router-dom";
import { getSessionToken, fetchMe } from "../api/auth";

export default function ProtectedRoute({ children }: { children: React.ReactNode }) {
  const navigate = useNavigate();
  const [checking, setChecking] = useState(true);

  useEffect(() => {
    const token = getSessionToken();
    if (!token) {
      navigate("/login", { replace: true });
      return;
    }

    // Verify token is still valid
    fetchMe()
      .then(() => setChecking(false))
      .catch(() => {
        navigate("/login", { replace: true });
      });
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
