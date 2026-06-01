import { motion } from "framer-motion";

type Props = {
  online: boolean;
  lastHeartbeat: string | null;
  scanActive: boolean;
};

function Node({ label, sub, status }: { label: string; sub: string; status: "ok" | "off" }) {
  return (
    <div className="topo-node">
      <span className={`topo-dot ${status === "ok" ? "topo-dot-ok" : "topo-dot-off"}`} />
      <div className="topo-node-label">{label}</div>
      <div className="topo-node-sub">{sub}</div>
    </div>
  );
}

function Link({ flowing, delay }: { flowing: boolean; delay: number }) {
  return (
    <div className={`topo-link ${flowing ? "topo-link-active" : ""}`}>
      {flowing && (
        <motion.span
          className="topo-packet"
          animate={{ left: ["0%", "100%"] }}
          transition={{ duration: 1.4, repeat: Infinity, ease: "linear", delay }}
        />
      )}
    </div>
  );
}

/** Diagrama live a conexiunii Agent -> Backend -> Platforma. Statusul nodului
 *  Agent vine din `is_online` + `last_heartbeat`; Backend si Platforma sunt
 *  mereu active (esti in UI). Cand agentul e online sau o scanare e in curs,
 *  pachete animate curg pe linii (flux de date). */
export function ConnectionTopology({ online, scanActive }: Props) {
  const agentSub = online ? "Online" : "Offline";
  const flowing = online || scanActive;
  return (
    <div className="topo" aria-label="Diagrama conexiune agent backend platforma">
      <Node label="Agent (PC-ul tau)" sub={agentSub} status={online ? "ok" : "off"} />
      <Link flowing={flowing} delay={0} />
      <Node label="Backend (API)" sub="FastAPI" status="ok" />
      <Link flowing={flowing} delay={0.7} />
      <Node label="Platform (UI)" sub="React" status="ok" />
    </div>
  );
}
