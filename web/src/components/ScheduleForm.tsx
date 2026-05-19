import { useState } from "react";
import { createSchedule } from "../api/exposure";
import type { ScanType, ScheduleFrequency } from "../api/types";

interface Props {
  deviceUid: string;
  onCreated: () => void;
}

const DAYS = ["Luni", "Marți", "Miercuri", "Joi", "Vineri", "Sâmbătă", "Duminică"];

export default function ScheduleForm({ deviceUid, onCreated }: Props) {
  const [scanType, setScanType] = useState<ScanType>("standard");
  const [frequency, setFrequency] = useState<ScheduleFrequency>("daily");
  const [hour, setHour] = useState(3);
  const [dow, setDow] = useState(0);
  const [dom, setDom] = useState(1);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  async function submit() {
    setBusy(true);
    setError(null);
    try {
      const body: Parameters<typeof createSchedule>[1] = {
        scan_type: scanType,
        frequency,
        hour,
      };
      if (frequency === "weekly") body.day_of_week = dow;
      if (frequency === "monthly") body.day_of_month = dom;
      await createSchedule(deviceUid, body);
      onCreated();
    } catch (e) {
      setError(e instanceof Error ? e.message : "Eroare la creare schedule");
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className="schedule-form">
      <select className="schedule-input" value={scanType}
              onChange={e => setScanType(e.target.value as ScanType)}>
        <option value="standard">Standard</option>
        <option value="advanced">Advanced</option>
        <option value="deep">Deep</option>
      </select>
      <select className="schedule-input" value={frequency}
              onChange={e => setFrequency(e.target.value as ScheduleFrequency)}>
        <option value="daily">Zilnic</option>
        <option value="weekly">Săptămânal</option>
        <option value="monthly">Lunar</option>
      </select>
      {frequency === "weekly" && (
        <select className="schedule-input" value={dow}
                onChange={e => setDow(Number(e.target.value))}>
          {DAYS.map((d, i) => <option key={i} value={i}>{d}</option>)}
        </select>
      )}
      {frequency === "monthly" && (
        <select className="schedule-input" value={dom}
                onChange={e => setDom(Number(e.target.value))}>
          {Array.from({ length: 28 }, (_, i) => i + 1).map(d => (
            <option key={d} value={d}>Ziua {d}</option>
          ))}
        </select>
      )}
      <select className="schedule-input" value={hour}
              onChange={e => setHour(Number(e.target.value))}>
        {Array.from({ length: 24 }, (_, i) => i).map(h => (
          <option key={h} value={h}>{String(h).padStart(2, "0")}:00 UTC</option>
        ))}
      </select>
      <button className="btn btn-primary btn-sm" onClick={submit} disabled={busy}>
        {busy ? "..." : "+ Adaugă"}
      </button>
      {error && (
        <div style={{ color: "var(--danger)", fontSize: 11, width: "100%" }}>
          {error}
        </div>
      )}
    </div>
  );
}
