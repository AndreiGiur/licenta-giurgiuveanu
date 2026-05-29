/**
 * Hook: incarca detaliul unui scan dupa id, cu anulare la schimbarea id-ului
 * sau la unmount (evita setState pe o componenta demontata / race conditions).
 *
 * Intoarce `{ detail, error }`. `detail` e null cat timp nu exista scan selectat
 * sau pana la sosirea raspunsului.
 */
import { useEffect, useState } from "react";
import { getScan } from "../api/exposure";
import type { ScanDetailResponse } from "../api/types";

export function useScanDetail(scanId: number | null): {
  detail: ScanDetailResponse | null;
  error: string | null;
} {
  const [detail, setDetail] = useState<ScanDetailResponse | null>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    if (!scanId) {
      setDetail(null);
      return;
    }
    let cancel = false;
    (async () => {
      try {
        const d = await getScan(scanId);
        if (!cancel) setDetail(d);
      } catch (e) {
        if (!cancel) setError(e instanceof Error ? e.message : "Eroare necunoscută");
      }
    })();
    return () => { cancel = true; };
  }, [scanId]);

  return { detail, error };
}
