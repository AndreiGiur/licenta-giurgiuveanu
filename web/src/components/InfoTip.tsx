import {
  useEffect, useLayoutEffect, useRef, useState, useId, type ReactNode,
} from "react";
import { createPortal } from "react-dom";
import { motion } from "framer-motion";
import { HELP, type HelpEntry } from "../help/helpContent";

type Placement = "top" | "bottom";

interface Props {
  /** Cheie in dictionarul HELP (help/helpContent.ts). */
  topic?: string;
  /** Titlu inline (suprascrie dictionarul). */
  title?: string;
  /** Continut inline (suprascrie dictionarul). */
  body?: ReactNode;
  /** Diametrul butonului in px (default 16). */
  size?: number;
  className?: string;
}

const POP_W = 280;
const GAP = 8;

/**
 * Buton mic "i" care arata o explicatie scurta intr-un popover.
 * - click = fixeaza popover-ul (sticky) pana la Escape / click in afara
 * - hover / focus pe desktop = arata temporar
 * Popover-ul e randat intr-un portal (pozitie fixa, auto-flip sus/jos) ca sa nu
 * fie taiat de containere cu overflow:hidden. Accesibil cu tastatura.
 */
export function InfoTip({ topic, title, body, size = 16, className }: Props) {
  const entry: HelpEntry | undefined = topic ? HELP[topic] : undefined;
  const t = title ?? entry?.title ?? "Informatie";
  const b = body ?? entry?.body ?? "";

  if (import.meta.env.DEV && topic && !entry && title === undefined) {
    // ajuta la prinderea unui topic gresit scris in timpul dezvoltarii
    console.warn(`[InfoTip] topic necunoscut: "${topic}"`);
  }

  const [show, setShow] = useState(false);
  const [pos, setPos] = useState<{ top: number; left: number; placement: Placement }>(
    { top: -9999, left: -9999, placement: "bottom" }
  );
  const btnRef = useRef<HTMLButtonElement>(null);
  const popRef = useRef<HTMLDivElement>(null);
  const pinnedRef = useRef(false);
  const closeTimer = useRef<number | undefined>(undefined);
  const id = useId();

  function reposition() {
    const btn = btnRef.current;
    if (!btn) return;
    const r = btn.getBoundingClientRect();
    const vw = window.innerWidth;
    const vh = window.innerHeight;
    let left = r.left + r.width / 2 - POP_W / 2;
    left = Math.max(8, Math.min(left, vw - POP_W - 8));
    const popH = popRef.current?.offsetHeight ?? 120;
    let placement: Placement = "bottom";
    let top = r.bottom + GAP;
    if (top + popH > vh - 8 && r.top - GAP - popH > 8) {
      placement = "top";
      top = r.top - GAP - popH;
    }
    setPos({ top, left, placement });
  }

  function openNow() {
    if (closeTimer.current) window.clearTimeout(closeTimer.current);
    setShow(true);
  }
  function scheduleClose() {
    if (closeTimer.current) window.clearTimeout(closeTimer.current);
    closeTimer.current = window.setTimeout(() => {
      if (!pinnedRef.current) setShow(false);
    }, 140);
  }
  function togglePin(e: React.MouseEvent) {
    e.stopPropagation();
    pinnedRef.current = !pinnedRef.current;
    setShow(pinnedRef.current ? true : false);
  }
  function close() {
    pinnedRef.current = false;
    setShow(false);
  }

  // Pozitionare (inainte de paint) + reasezare la scroll/resize cat e deschis.
  useLayoutEffect(() => {
    if (!show) return;
    reposition();
    const onMove = () => reposition();
    window.addEventListener("scroll", onMove, true);
    window.addEventListener("resize", onMove);
    return () => {
      window.removeEventListener("scroll", onMove, true);
      window.removeEventListener("resize", onMove);
    };
  }, [show]);

  // Escape + click in afara inchid popover-ul.
  useEffect(() => {
    if (!show) return;
    function onKey(e: KeyboardEvent) {
      if (e.key === "Escape") close();
    }
    function onDocDown(e: MouseEvent) {
      const target = e.target as Node;
      if (btnRef.current?.contains(target) || popRef.current?.contains(target)) return;
      close();
    }
    document.addEventListener("keydown", onKey);
    document.addEventListener("mousedown", onDocDown);
    return () => {
      document.removeEventListener("keydown", onKey);
      document.removeEventListener("mousedown", onDocDown);
    };
  }, [show]);

  useEffect(() => () => {
    if (closeTimer.current) window.clearTimeout(closeTimer.current);
  }, []);

  return (
    <>
      <button
        ref={btnRef}
        type="button"
        className={`infotip-btn${className ? " " + className : ""}`}
        style={{ width: size, height: size }}
        aria-label={`Informatii: ${t}`}
        aria-expanded={show}
        aria-describedby={show ? id : undefined}
        onClick={togglePin}
        onMouseEnter={openNow}
        onMouseLeave={scheduleClose}
        onFocus={openNow}
        onBlur={scheduleClose}
      >
        i
      </button>
      {show && createPortal(
        <motion.div
          ref={popRef}
          id={id}
          role="note"
          className={`infotip-pop infotip-pop-${pos.placement}`}
          style={{ position: "fixed", top: pos.top, left: pos.left, width: POP_W, zIndex: 1000 }}
          initial={{ opacity: 0, scale: 0.96 }}
          animate={{ opacity: 1, scale: 1 }}
          transition={{ duration: 0.13, ease: "easeOut" }}
          onMouseEnter={openNow}
          onMouseLeave={scheduleClose}
        >
          <div className="infotip-title">{t}</div>
          <div className="infotip-body">{b}</div>
        </motion.div>,
        document.body
      )}
    </>
  );
}
