import { BrowserRouter, Routes, Route, Navigate } from "react-router-dom";
import UnifiedDashboard from "./pages/UnifiedDashboard";
import ScanDetail from "./pages/ScanDetail";
import Register from "./pages/Register";
import Login from "./pages/Login";
import Profile from "./pages/Profile";
import Admin from "./pages/Admin";
import ProtectedRoute from "./components/ProtectedRoute";

export default function App() {
  return (
    <BrowserRouter>
      <Routes>
        <Route path="/register" element={<Register />} />
        <Route path="/login" element={<Login />} />
        <Route
          path="/dashboard"
          element={
            <ProtectedRoute>
              <UnifiedDashboard />
            </ProtectedRoute>
          }
        />
        {/* /devices a fost unificat in /dashboard — pastram redirect pentru linkuri vechi */}
        <Route path="/devices" element={<Navigate to="/dashboard" replace />} />
        <Route
          path="/scans/:scanId"
          element={
            <ProtectedRoute>
              <ScanDetail />
            </ProtectedRoute>
          }
        />
        <Route
          path="/profile"
          element={
            <ProtectedRoute>
              <Profile />
            </ProtectedRoute>
          }
        />
        <Route
          path="/admin"
          element={
            <ProtectedRoute requireAdmin>
              <Admin />
            </ProtectedRoute>
          }
        />
        <Route path="/" element={<Navigate to="/login" replace />} />
      </Routes>
    </BrowserRouter>
  );
}
