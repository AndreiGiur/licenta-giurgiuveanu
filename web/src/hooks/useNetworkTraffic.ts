/**
 * Hook: polling-ul seriei de trafic de retea live pentru un device.
 *
 * Polleaza `GET /devices/{uid}/net-traffic` la 10s (cadenta heartbeat-ului).
 * Intoarce seria curenta (ultimele ~10 min). Gol cand uid lipseste sau agentul
 * e offline (fara sample-uri). Best-effort: erorile de retea nu arunca.
 */
import { useEffect, useState } from "react";
import { getNetTraffic } from "../api/exposure";
import type { NetTrafficPoint } from "../api/types";

const POLL_MS = 10000;

export function useNetworkTraffic(deviceUid: string): NetTrafficPoint[] {
  const [series, setSeries] = useState<NetTrafficPoint[]>([]);

  useEffect(() => {
    const uid = deviceUid.trim();
    if (!uid) {
      setSeries([]);
      return;
    }
    let cancelled = false;
    let timer: ReturnType<typeof setTimeout> | null = null;

    async function tick() {
      try {
        const data = await getNetTraffic(uid);
        if (!cancelled) setSeries(data);
      } catch {
        /* offline / fara date — pastram ultima serie */
      }
      if (!cancelled) timer = setTimeout(tick, POLL_MS);
    }
    tick();
    return () => { cancelled = true; if (timer) clearTimeout(timer); };
  }, [deviceUid]);

  return series;
}
