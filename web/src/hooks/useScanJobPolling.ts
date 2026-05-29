/**
 * Hook: polling-ul job-ului activ (pending/running) pentru un device.
 *
 * Scanarile advanced/deep dureaza minute, asa ca UI-ul afiseaza un progress bar
 * live. Acest hook polleaza `listScanJobs` la fiecare 2s si:
 *  - intoarce job-ul activ (sau null) pentru progress bar
 *  - apeleaza `onJobDone()` cand un job tocmai s-a finalizat (scan nou disponibil)
 *
 * Callback-ul e tinut intr-un ref ca sa nu re-declanseze effect-ul la fiecare
 * render (effect-ul depinde DOAR de `deviceUid`).
 */
import { useEffect, useRef, useState } from "react";
import { listScanJobs } from "../api/exposure";
import type { ScanJobResponse } from "../api/types";

const POLL_INTERVAL_MS = 2000;

export function useScanJobPolling(
  deviceUid: string,
  onJobDone: () => void,
): ScanJobResponse | null {
  const [activeJob, setActiveJob] = useState<ScanJobResponse | null>(null);

  // Ref pentru ultimul callback — evita re-subscribe la fiecare render.
  const onJobDoneRef = useRef(onJobDone);
  onJobDoneRef.current = onJobDone;

  useEffect(() => {
    const uid = deviceUid.trim();
    if (!uid) {
      setActiveJob(null);
      return;
    }
    let cancelled = false;
    let timer: ReturnType<typeof setTimeout> | null = null;
    const lastDoneId = { current: null as number | null };

    async function tick() {
      try {
        const jobs = await listScanJobs(uid);
        if (cancelled) return;
        const active = jobs.find(j => j.status === "running" || j.status === "pending");
        setActiveJob(active ?? null);
        // Daca tocmai a terminat un job (scan nou), anunta consumatorul.
        const newest = jobs.find(j => j.status === "done");
        if (!active && newest && newest.scan_id && newest.scan_id !== lastDoneId.current) {
          lastDoneId.current = newest.scan_id;
          onJobDoneRef.current();
        }
      } catch {
        if (!cancelled) setActiveJob(null);
      }
      if (!cancelled) timer = setTimeout(tick, POLL_INTERVAL_MS);
    }
    tick();
    return () => { cancelled = true; if (timer) clearTimeout(timer); };
  }, [deviceUid]);

  return activeJob;
}
