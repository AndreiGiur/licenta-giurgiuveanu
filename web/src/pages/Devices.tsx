import { useState, useEffect } from "react";
import { useNavigate } from "react-router-dom";
import Navbar from "../components/Navbar";
import { http } from "../api/http";
import { getSessionToken } from "../api/auth";

type Device = {
  id: number;
  device_uid: string;
  name: string;
  created_at: string;
};

type DeviceCreateResponse = Device & {
  device_token: string;
};

export default function Devices() {
  const navigate = useNavigate();
  const [devices, setDevices] = useState<Device[]>([]);
  const [loading, setLoading] = useState(true);
  const [creating, setCreating] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const [newDeviceUid, setNewDeviceUid] = useState("");
  const [newDeviceName, setNewDeviceName] = useState("");
  const [createdToken, setCreatedToken] = useState<string | null>(null);

  useEffect(() => {
    loadDevices();
  }, []);

  async function loadDevices() {
    setLoading(true);
    setError(null);
    try {
      const token = getSessionToken();
      if (!token) throw new Error("Missing token");

      const data = await http<Device[]>("/api/v1/devices", {
        method: "GET",
        headers: { "X-Session-Token": token },
      });
      setDevices(data);
    } catch (e) {
      setError(e instanceof Error ? e.message : "Unknown error");
    } finally {
      setLoading(false);
    }
  }

  async function handleCreate(e: React.FormEvent) {
    e.preventDefault();
    setError(null);
    setCreating(true);
    setCreatedToken(null);

    try {
      const token = getSessionToken();
      if (!token) throw new Error("Missing token");

      const created = await http<DeviceCreateResponse>("/api/v1/devices", {
        method: "POST",
        headers: { "X-Session-Token": token },
        body: {
          device_uid: newDeviceUid.trim(),
          name: newDeviceName.trim(),
        },
      });

      setCreatedToken(created.device_token);
      setNewDeviceUid("");
      setNewDeviceName("");
      await loadDevices();
    } catch (e) {
      setError(e instanceof Error ? e.message : "Failed to create device");
    } finally {
      setCreating(false);
    }
  }

  return (
    <div
      style={{
        fontFamily: "system-ui, -apple-system, Segoe UI, Roboto, Arial, sans-serif",
        minHeight: "100vh",
        background: "#fafafa",
      }}
    >
      <Navbar />
      <div style={{ maxWidth: 900, margin: "40px auto", padding: "0 16px" }}>
        <h1 style={{ margin: 0, fontSize: 24, fontWeight: 800 }}>Devices</h1>

        {error && (
          <div
            style={{
              marginTop: 16,
              padding: 12,
              borderRadius: 12,
              border: "1px solid #f2b8b8",
              background: "#fff5f5",
            }}
          >
            <div style={{ fontWeight: 800, marginBottom: 6 }}>Error</div>
            <div style={{ fontSize: 13 }}>{error}</div>
          </div>
        )}

        {createdToken && (
          <div
            style={{
              marginTop: 16,
              padding: 14,
              borderRadius: 12,
              border: "1px solid #bfe8c5",
              background: "#f0fdf4",
            }}
          >
            <div style={{ fontWeight: 800, marginBottom: 8 }}>Device enrolled!</div>
            <div style={{ fontSize: 13, marginBottom: 8 }}>
              Copy this token for your agent. It won't be shown again:
            </div>
            <div
              style={{
                background: "#0f0f0f",
                color: "#22c55e",
                padding: 10,
                borderRadius: 8,
                fontFamily: "monospace",
                fontSize: 13,
                wordBreak: "break-all",
              }}
            >
              {createdToken}
            </div>
          </div>
        )}

        <div
          style={{
            marginTop: 20,
            border: "1px solid #e5e5e5",
            borderRadius: 14,
            padding: 16,
            background: "white",
          }}
        >
          <div style={{ fontWeight: 800, marginBottom: 12 }}>Enroll new device</div>
          <form onSubmit={handleCreate}>
            <label style={{ display: "block", fontSize: 13, marginBottom: 6, fontWeight: 600 }}>
              Device UID
            </label>
            <input
              value={newDeviceUid}
              onChange={(e) => setNewDeviceUid(e.target.value)}
              placeholder="e.g., laptop-work, desktop-home"
              required
              style={{
                width: "100%",
                height: 40,
                padding: "0 12px",
                borderRadius: 10,
                border: "1px solid #d4d4d4",
                outline: "none",
                marginBottom: 12,
              }}
            />

            <label style={{ display: "block", fontSize: 13, marginBottom: 6, fontWeight: 600 }}>
              Name
            </label>
            <input
              value={newDeviceName}
              onChange={(e) => setNewDeviceName(e.target.value)}
              placeholder="e.g., My Work Laptop"
              required
              style={{
                width: "100%",
                height: 40,
                padding: "0 12px",
                borderRadius: 10,
                border: "1px solid #d4d4d4",
                outline: "none",
                marginBottom: 12,
              }}
            />

            <button
              type="submit"
              disabled={creating}
              style={{
                width: "100%",
                height: 42,
                borderRadius: 12,
                border: "none",
                background: "#0f0f0f",
                color: "white",
                fontWeight: 700,
                cursor: creating ? "not-allowed" : "pointer",
                opacity: creating ? 0.5 : 1,
              }}
            >
              {creating ? "Creating..." : "Enroll Device"}
            </button>
          </form>
        </div>

        <div style={{ marginTop: 20 }}>
          <div style={{ fontWeight: 800, marginBottom: 12 }}>Your devices ({devices.length})</div>

          {loading && <div style={{ fontSize: 13, opacity: 0.7 }}>Loading...</div>}

          {!loading && devices.length === 0 && (
            <div
              style={{
                padding: 20,
                border: "1px solid #e5e5e5",
                borderRadius: 14,
                background: "white",
                textAlign: "center",
                fontSize: 13,
                opacity: 0.7,
              }}
            >
              No devices enrolled yet. Create one above.
            </div>
          )}

          {!loading && devices.length > 0 && (
            <div style={{ display: "flex", flexDirection: "column", gap: 10 }}>
              {devices.map((d) => (
                <div
                  key={d.id}
                  style={{
                    border: "1px solid #e5e5e5",
                    borderRadius: 14,
                    padding: 14,
                    background: "white",
                  }}
                >
                  <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center" }}>
                    <div>
                      <div style={{ fontWeight: 800 }}>{d.name}</div>
                      <div style={{ fontSize: 13, opacity: 0.7, marginTop: 2 }}>UID: {d.device_uid}</div>
                    </div>
                    <button
                      onClick={() => navigate(`/dashboard?device=${d.device_uid}`)}
                      style={{
                        background: "#0f0f0f",
                        color: "white",
                        border: "none",
                        borderRadius: 8,
                        padding: "6px 14px",
                        fontWeight: 700,
                        cursor: "pointer",
                        fontSize: 13,
                      }}
                    >
                      View Scans
                    </button>
                  </div>
                  <div style={{ fontSize: 11, opacity: 0.5, marginTop: 6 }}>
                    Created: {new Date(d.created_at).toLocaleString()}
                  </div>
                </div>
              ))}
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
