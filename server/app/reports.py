"""Generator PDF rapoarte scan — paleta Honey & Plum."""
from __future__ import annotations

import json
import unicodedata
from datetime import datetime, timezone
from io import BytesIO

from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import cm
from reportlab.platypus import (
    PageBreak,
    Paragraph,
    SimpleDocTemplate,
    Spacer,
    Table,
    TableStyle,
)

# ── Paleta Ocean (oglindeste FE — web/src/index.css, valorile light) ─────────
# Numele istorice (PLUM/HONEY/CREAM...) sunt pastrate ca alias ca sa nu atingem
# zecile de referinte; valorile sunt acum Ocean (albastru + teal).
PLUM = colors.HexColor("#0f2942")        # navy — text/headere
HONEY = colors.HexColor("#2563eb")       # albastru — accent primar
CREAM = colors.HexColor("#f6f9fc")       # fundal deschis
CREAM_ALT = colors.HexColor("#eef4fb")   # fundal coloana
RASPBERRY = colors.HexColor("#ef4444")   # severity high
LAVENDER = colors.HexColor("#38bdf8")    # severity low (sky)
MUTED = colors.HexColor("#6b8299")
BORDER = colors.HexColor("#d8e3f0")
PLUM_DEEP = colors.HexColor("#b91c1c")   # severity critical (deep red)
TEAL = colors.HexColor("#0d9488")        # accent secundar
AMBER = colors.HexColor("#f59e0b")       # severity medium

SEVERITY_COLOR = {
    "critical": PLUM_DEEP,   # #b91c1c
    "high": RASPBERRY,       # #ef4444
    "medium": AMBER,         # #f59e0b (HONEY e acum albastru → folosim amber)
    "low": LAVENDER,         # #38bdf8
    "info": MUTED,
}


def _ascii(s) -> str:
    """Transliterare ASCII: elimina diacritice + caractere non-Latin1 pentru Helvetica."""
    if s is None:
        return ""
    text = str(s)
    nfkd = unicodedata.normalize("NFKD", text)
    no_marks = "".join(ch for ch in nfkd if not unicodedata.combining(ch))
    return no_marks.encode("ascii", "replace").decode("ascii")


def _ev_str(evidence) -> str:
    """Serializează evidence dict în text formatat pentru PDF."""
    if not evidence:
        return ""
    try:
        return json.dumps(evidence, indent=2, ensure_ascii=False, default=str)
    except (TypeError, ValueError):
        return str(evidence)


def _escape_html(s: str) -> str:
    """Escape minimal pentru Paragraph + transliterare ASCII pentru Helvetica."""
    safe = _ascii(s)
    return (safe.replace("&", "&amp;")
                .replace("<", "&lt;")
                .replace(">", "&gt;"))


def generate_scan_pdf(scan, device, findings, owner_email: str) -> bytes:
    """Generează PDF report pentru un scan. Returnează bytes."""
    buf = BytesIO()
    doc = SimpleDocTemplate(
        buf, pagesize=A4,
        topMargin=2 * cm, bottomMargin=2 * cm,
        leftMargin=2 * cm, rightMargin=2 * cm,
        title=f"VulnWatch Scan #{scan.id}",
        author="VulnWatch",
    )
    elements = []
    styles = getSampleStyleSheet()

    title_style = ParagraphStyle(
        "Title", parent=styles["Title"],
        textColor=PLUM, fontSize=26, alignment=1, spaceAfter=4,
    )
    subtitle_style = ParagraphStyle(
        "Subtitle", parent=styles["Heading2"],
        textColor=MUTED, fontSize=12, alignment=1, spaceAfter=16,
    )
    h2_style = ParagraphStyle(
        "H2", parent=styles["Heading2"],
        textColor=PLUM, fontSize=15, spaceAfter=10, spaceBefore=6,
    )
    body_style = ParagraphStyle(
        "Body", parent=styles["BodyText"],
        fontSize=10, textColor=PLUM, leading=14, spaceAfter=4,
    )
    small_style = ParagraphStyle(
        "Small", parent=styles["BodyText"],
        fontSize=8, textColor=MUTED, leading=11,
    )

    # ── Header ──
    elements.append(Paragraph("VulnWatch", title_style))
    elements.append(Paragraph("Raport de scanare securitate", subtitle_style))

    # ── Meta tabel ──
    payload = scan.payload or {}
    os_info = payload.get("os", {}) or {}
    meta_data = [
        ["Device", _ascii(device.name)],
        ["UID", _ascii(device.device_uid)],
        ["Owner", _ascii(owner_email)],
        ["OS", _ascii(f"{os_info.get('system', '?')} {os_info.get('release', '')}".strip())],
        ["Hostname", _ascii(os_info.get("hostname", "?"))],
        ["Scan type", (payload.get("scan_type") or "standard").upper()],
        ["Data", scan.created_at.strftime("%d %b %Y, %H:%M")],
        ["Scan ID", f"#{scan.id}"],
    ]
    meta_tbl = Table(meta_data, colWidths=[3.5 * cm, 12.5 * cm])
    meta_tbl.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (0, -1), CREAM_ALT),
        ("TEXTCOLOR", (0, 0), (0, -1), PLUM),
        ("TEXTCOLOR", (1, 0), (1, -1), PLUM),
        ("FONTNAME", (0, 0), (0, -1), "Helvetica-Bold"),
        ("FONTSIZE", (0, 0), (-1, -1), 10),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
        ("TOPPADDING", (0, 0), (-1, -1), 6),
        ("LEFTPADDING", (0, 0), (-1, -1), 8),
        ("RIGHTPADDING", (0, 0), (-1, -1), 8),
        ("GRID", (0, 0), (-1, -1), 0.5, BORDER),
    ]))
    elements.append(meta_tbl)
    elements.append(Spacer(1, 0.9 * cm))

    # ── Exposure score ──
    elements.append(Paragraph("Scor de expunere", h2_style))
    score = scan.exposure_score
    score_color = (
        SEVERITY_COLOR["critical"] if score >= 75 else
        SEVERITY_COLOR["high"] if score >= 50 else
        SEVERITY_COLOR["medium"] if score >= 25 else
        SEVERITY_COLOR["low"]
    )
    score_style = ParagraphStyle(
        "Score", parent=styles["Title"],
        textColor=score_color, fontSize=56, alignment=1, leading=64,
    )
    elements.append(Paragraph(
        f"{score}<font size=20 color='{MUTED.hexval()}'>/100</font>",
        score_style,
    ))
    elements.append(Spacer(1, 0.6 * cm))

    # ── Severity breakdown ──
    sev_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    for f in findings:
        sev = (f.severity or "info").lower()
        sev_counts[sev] = sev_counts.get(sev, 0) + 1

    sev_data = [["Severitate", "Numar"]]
    for sev in ["critical", "high", "medium", "low", "info"]:
        sev_data.append([sev.upper(), str(sev_counts[sev])])

    sev_tbl = Table(sev_data, colWidths=[10 * cm, 6 * cm])
    sev_style_cmds = [
        ("BACKGROUND", (0, 0), (-1, 0), PLUM),
        ("TEXTCOLOR", (0, 0), (-1, 0), CREAM),
        ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
        ("FONTSIZE", (0, 0), (-1, -1), 10),
        ("ALIGN", (1, 0), (1, -1), "CENTER"),
        ("GRID", (0, 0), (-1, -1), 0.5, BORDER),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 7),
        ("TOPPADDING", (0, 0), (-1, -1), 7),
        ("LEFTPADDING", (0, 0), (-1, -1), 10),
    ]
    for i, sev in enumerate(["critical", "high", "medium", "low", "info"], start=1):
        sev_style_cmds.append(("TEXTCOLOR", (0, i), (0, i), SEVERITY_COLOR[sev]))
        sev_style_cmds.append(("FONTNAME", (0, i), (0, i), "Helvetica-Bold"))
    sev_tbl.setStyle(TableStyle(sev_style_cmds))
    elements.append(sev_tbl)
    elements.append(Spacer(1, 0.8 * cm))

    # ── Score breakdown pe 4 categorii ──
    breakdown = getattr(scan, "score_breakdown", None) or {}
    if breakdown:
        elements.append(Paragraph("Score breakdown pe categorii", h2_style))
        breakdown_rows = [["Categorie", "Pondere", "Sub-scor"]]
        cat_labels = [
            ("critical_risk",    "Risc critic",       "40%"),
            ("network_exposure", "Expunere retea",    "30%"),
            ("hygiene",          "Igiena sistem",     "20%"),
            ("activity",         "Activitate suspecta", "10%"),
        ]
        for key, label, pct in cat_labels:
            val = breakdown.get(key, 0)
            breakdown_rows.append([label, pct, f"{val}/100"])
        bd_tbl = Table(breakdown_rows, colWidths=[7 * cm, 4 * cm, 5 * cm])
        bd_style_cmds = [
            ("BACKGROUND", (0, 0), (-1, 0), PLUM),
            ("TEXTCOLOR", (0, 0), (-1, 0), CREAM),
            ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
            ("FONTSIZE", (0, 0), (-1, -1), 10),
            ("ALIGN", (1, 0), (-1, -1), "CENTER"),
            ("GRID", (0, 0), (-1, -1), 0.5, BORDER),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 7),
            ("TOPPADDING", (0, 0), (-1, -1), 7),
            ("LEFTPADDING", (0, 0), (-1, -1), 10),
        ]
        for i, (_, _, _) in enumerate(cat_labels, start=1):
            val = breakdown.get(cat_labels[i - 1][0], 0)
            sev = "critical" if val >= 75 else "high" if val >= 50 else "medium" if val >= 25 else "low" if val > 0 else "info"
            bd_style_cmds.append(("TEXTCOLOR", (2, i), (2, i), SEVERITY_COLOR.get(sev, MUTED)))
            bd_style_cmds.append(("FONTNAME", (2, i), (2, i), "Helvetica-Bold"))
        bd_tbl.setStyle(TableStyle(bd_style_cmds))
        elements.append(bd_tbl)
        elements.append(Paragraph(
            f"<font size=8 color='{MUTED.hexval()}'>"
            "Scor agregat = 0.40 * Risc critic + 0.30 * Expunere retea + 0.20 * Igiena + 0.10 * Activitate"
            "</font>", small_style))
        elements.append(Spacer(1, 0.6 * cm))

    # ── Coverage standarde (CIS Controls v8 + NIST CSF 2.0) ──
    compliance_refs: dict[str, list[str]] = {}  # "CIS-9.2" -> [rule_id-uri care l-au declansat]
    for f in findings:
        for ref in (f.evidence.get("_compliance_at_finding", []) if False else (getattr(f, "compliance", None) or [])):
            compliance_refs.setdefault(ref, []).append(f.rule_id)
    # Fallback: ia compliance din finding dict (cum vine din evaluate()).
    if not compliance_refs:
        # Reincarca compliance per regula din _RULES.
        try:
            from .rules import _RULES
            rules_by_id = {fn._rule_id: getattr(fn, "_compliance", []) for fn in _RULES}
            for f in findings:
                for ref in rules_by_id.get(f.rule_id, []):
                    compliance_refs.setdefault(ref, []).append(f.rule_id)
        except Exception:
            pass

    if compliance_refs:
        elements.append(Paragraph("Coverage standarde de securitate", h2_style))
        # Grupare pe framework (prefix CIS vs NIST).
        cis_refs = sorted([r for r in compliance_refs if r.startswith("CIS-")])
        nist_refs = sorted([r for r in compliance_refs if r.startswith("NIST-")])

        cmpl_rows = [["Framework", "Control afectat", "Reguli care semnaleaza"]]
        for ref in cis_refs:
            rules_str = ", ".join(sorted(set(compliance_refs[ref])))
            cmpl_rows.append(["CIS Controls v8", ref.replace("CIS-", ""), rules_str])
        for ref in nist_refs:
            rules_str = ", ".join(sorted(set(compliance_refs[ref])))
            cmpl_rows.append(["NIST CSF 2.0", ref.replace("NIST-", ""), rules_str])

        cmpl_tbl = Table(cmpl_rows, colWidths=[4 * cm, 4 * cm, 8 * cm])
        cmpl_style_cmds = [
            ("BACKGROUND", (0, 0), (-1, 0), PLUM),
            ("TEXTCOLOR", (0, 0), (-1, 0), CREAM),
            ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
            ("FONTSIZE", (0, 0), (-1, -1), 9),
            ("GRID", (0, 0), (-1, -1), 0.5, BORDER),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
            ("TOPPADDING", (0, 0), (-1, -1), 6),
            ("LEFTPADDING", (0, 0), (-1, -1), 8),
            ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ]
        cmpl_tbl.setStyle(TableStyle(cmpl_style_cmds))
        elements.append(cmpl_tbl)
        elements.append(Paragraph(
            f"<font size=8 color='{MUTED.hexval()}'>"
            f"{len(cis_refs)} controale CIS Controls v8 + {len(nist_refs)} subcategorii NIST CSF 2.0 "
            "afectate de vulnerabilitatile detectate. Sursa: cisecurity.org/controls, nist.gov/cyberframework."
            "</font>", small_style))
        elements.append(Spacer(1, 0.6 * cm))

    # ── Findings detaliate ──
    elements.append(PageBreak())
    elements.append(Paragraph("Vulnerabilitati detectate", h2_style))
    elements.append(Spacer(1, 0.3 * cm))

    if not findings:
        elements.append(Paragraph(
            "<font color='#7a9a5a'>OK</font> Sistem curat - nicio vulnerabilitate detectata.",
            body_style,
        ))
    else:
        # Sortare după severity (critical → info)
        sev_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
        sorted_findings = sorted(
            findings, key=lambda f: sev_order.get((f.severity or "info").lower(), 5))
        for f in sorted_findings:
            sev = (f.severity or "info").lower()
            color = SEVERITY_COLOR.get(sev, MUTED)
            title_text = (
                f"<font color='{color.hexval()}'><b>[{sev.upper()}]</b></font> "
                f"<b>{_escape_html(f.title)}</b>  "
                f"<font size=8 color='{MUTED.hexval()}'>({_escape_html(f.rule_id)})</font>"
            )
            elements.append(Paragraph(title_text, body_style))

            ev_text = _ev_str(f.evidence)
            if ev_text:
                ev_safe = _escape_html(ev_text).replace("\n", "<br/>").replace(" ", "&nbsp;")
                elements.append(Paragraph(
                    f"<font face='Courier' size=8 color='{MUTED.hexval()}'>{ev_safe}</font>",
                    body_style,
                ))

            if f.recommendation:
                elements.append(Paragraph(
                    f"<i>Recomandare:</i> {_escape_html(f.recommendation)}",
                    body_style,
                ))
            elements.append(Spacer(1, 0.3 * cm))

    # ── Nmap section ──
    nmap = payload.get("nmap") if payload else None
    if nmap and nmap.get("hosts"):
        elements.append(PageBreak())
        elements.append(Paragraph(
            f"Network scan (nmap {nmap.get('version', '?')})", h2_style))
        targets = ", ".join(nmap.get("targets", []) or [])
        elements.append(Paragraph(f"<b>Targets:</b> {_escape_html(targets)}", small_style))
        scope = "subnet local" if nmap.get("subnet_scan") else "host"
        elements.append(Paragraph(
            f"<b>Durata:</b> {nmap.get('scan_time_sec', '?')}s - "
            f"{len(nmap['hosts'])} host-uri descoperite ({scope})", small_style))
        elements.append(Spacer(1, 0.4 * cm))

        # ── Tabel retea: IP / MAC / Vendor / Hostname / OS / #porturi ──
        net_rows = [["IP", "MAC", "Vendor", "Hostname", "OS", "Porturi"]]
        for host in nmap["hosts"]:
            open_ports = [p for p in (host.get("ports") or []) if p.get("state") == "open"]
            os_short = (host.get("os_guess") or "").split(" (")[0]
            net_rows.append([
                _ascii(host.get("ip", "?")),
                _ascii(host.get("mac", "") or "-"),
                _ascii((host.get("vendor", "") or "-")[:22]),
                _ascii((host.get("hostname", "") or "-")[:18]),
                _ascii(os_short[:22] or "-"),
                str(len(open_ports)),
            ])
        net_tbl = Table(net_rows, colWidths=[3 * cm, 3.2 * cm, 3.3 * cm, 2.5 * cm, 2.5 * cm, 1.5 * cm])
        net_tbl.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), PLUM),
            ("TEXTCOLOR", (0, 0), (-1, 0), CREAM),
            ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
            ("FONTSIZE", (0, 0), (-1, -1), 8),
            ("ALIGN", (5, 0), (5, -1), "CENTER"),
            ("GRID", (0, 0), (-1, -1), 0.5, BORDER),
            ("ROWBACKGROUNDS", (0, 1), (-1, -1), [CREAM, CREAM_ALT]),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
            ("TOPPADDING", (0, 0), (-1, -1), 5),
            ("LEFTPADDING", (0, 0), (-1, -1), 6),
        ]))
        elements.append(net_tbl)
        elements.append(Spacer(1, 0.6 * cm))

        # ── Detaliu per host ──
        for host in nmap["hosts"]:
            ip = _escape_html(host.get("ip", "?"))
            hostname = _escape_html(host.get("hostname", "n/a"))
            mac = host.get("mac", "")
            mac_txt = f" - MAC {_escape_html(mac)}" if mac else ""
            vendor = host.get("vendor", "")
            vendor_txt = f" ({_escape_html(vendor)})" if vendor else ""
            elements.append(Paragraph(
                f"<b>{ip}</b> "
                f"<font size=9 color='{MUTED.hexval()}'>({hostname}){mac_txt}{vendor_txt}</font>",
                body_style,
            ))
            if host.get("os_guess"):
                elements.append(Paragraph(
                    f"OS: {_escape_html(host['os_guess'])}", small_style))
            open_ports = [p for p in (host.get("ports") or []) if p.get("state") == "open"]
            for p in open_ports:
                version = (p.get("version") or "").strip()
                cpe = (p.get("cpe") or "").strip()
                line = (f"{p.get('port')}/{p.get('proto', '?')} "
                        f"{p.get('service', '?')}")
                if version:
                    line += f" - {version}"
                if cpe:
                    line += f" [{cpe}]"
                elements.append(Paragraph(
                    f"<font face='Courier' size=8>{_escape_html(line)}</font>", small_style))
            vuln_findings = host.get("vulnwatch_findings") or []
            for vf in vuln_findings:
                sev = (vf.get("severity") or "info").lower()
                color = SEVERITY_COLOR.get(sev, MUTED)
                elements.append(Paragraph(
                    f"<font color='{color.hexval()}'><b>[{sev.upper()}]</b></font> "
                    f"{_escape_html(vf.get('title', '?'))}",
                    small_style,
                ))
                ev = vf.get("evidence") or vf.get("description")
                if ev:
                    ev_safe = _escape_html(_ev_str(ev) if isinstance(ev, (dict, list)) else str(ev))
                    ev_safe = ev_safe.replace("\n", "<br/>")
                    elements.append(Paragraph(
                        f"<font face='Courier' size=7 color='{MUTED.hexval()}'>{ev_safe}</font>",
                        small_style))
                if vf.get("recommendation"):
                    elements.append(Paragraph(
                        f"<i>Recomandare:</i> {_escape_html(vf['recommendation'])}", small_style))
            elements.append(Spacer(1, 0.4 * cm))

    # ── Sectiune audit Linux ──
    linux = payload.get("linux") if payload else None
    is_linux = str(os_info.get("system", "")).lower().startswith("linux")
    if is_linux and linux:
        elements.append(PageBreak())
        elements.append(Paragraph("Audit Linux (date colectate)", h2_style))

        ssh = linux.get("ssh") or {}
        if ssh:
            ssh_line = ", ".join(f"{k}={v}" for k, v in ssh.items())
            elements.append(Paragraph(f"<b>SSH:</b> {_escape_html(ssh_line)}", small_style))

        fw = linux.get("firewall") or {}
        if fw:
            elements.append(Paragraph(
                f"<b>Firewall:</b> {_escape_html(fw.get('tool', '?'))} - "
                f"{'activ' if fw.get('active') else 'inactiv'}", small_style))

        users = linux.get("users") or {}
        uid0 = users.get("uid0_accounts") or []
        empty = users.get("empty_password_accounts") or []
        nopw = users.get("sudo_nopasswd") or []
        if uid0:
            elements.append(Paragraph(f"<b>Conturi UID 0:</b> {_escape_html(', '.join(uid0))}", small_style))
        if empty:
            elements.append(Paragraph(f"<b>Conturi cu parola goala:</b> {_escape_html(', '.join(empty))}", small_style))
        if nopw:
            elements.append(Paragraph(f"<b>sudo NOPASSWD:</b> {len(nopw)} reguli", small_style))

        sysctl = linux.get("sysctl") or {}
        if sysctl:
            sc_line = ", ".join(f"{k}={v}" for k, v in sysctl.items())
            elements.append(Paragraph(f"<b>sysctl:</b> {_escape_html(sc_line)}", small_style))

        for label, key in [("SUID neobisnuite", "suid"), ("SGID neobisnuite", "sgid"),
                           ("World-writable", "world_writable")]:
            items = linux.get(key) or []
            if items:
                elements.append(Paragraph(
                    f"<b>{label}:</b> {_escape_html(', '.join(items[:15]))}"
                    + (" ..." if len(items) > 15 else ""), small_style))

        if linux.get("kernel"):
            elements.append(Paragraph(f"<b>Kernel:</b> {_escape_html(linux['kernel'])}", small_style))
        elements.append(Spacer(1, 0.4 * cm))

    # ── Footer ──
    elements.append(Spacer(1, 0.6 * cm))
    generated_at = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    elements.append(Paragraph(
        f"<font size=8 color='{MUTED.hexval()}'>"
        f"Generat de VulnWatch - {generated_at}</font>",
        small_style,
    ))

    doc.build(elements)
    return buf.getvalue()
