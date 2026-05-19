"""Generator PDF rapoarte scan — paleta Honey & Plum."""
from __future__ import annotations

import json
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

# ── Paleta Honey & Plum ──────────────────────────────────────────────────────
PLUM = colors.HexColor("#2d1b3d")
HONEY = colors.HexColor("#f4c95d")
CREAM = colors.HexColor("#fefaf2")
CREAM_ALT = colors.HexColor("#fff8e6")
RASPBERRY = colors.HexColor("#b8456e")
LAVENDER = colors.HexColor("#a8639a")
MUTED = colors.HexColor("#8a7458")
BORDER = colors.HexColor("#f0e4cc")
PLUM_DEEP = colors.HexColor("#5a2d6e")

SEVERITY_COLOR = {
    "critical": PLUM_DEEP,
    "high": RASPBERRY,
    "medium": HONEY,
    "low": LAVENDER,
    "info": MUTED,
}


def _ev_str(evidence) -> str:
    """Serializează evidence dict în text formatat pentru PDF."""
    if not evidence:
        return ""
    try:
        return json.dumps(evidence, indent=2, ensure_ascii=False, default=str)
    except (TypeError, ValueError):
        return str(evidence)


def _escape_html(s: str) -> str:
    """Escape minimal pentru Paragraph (care interpretează tag-uri HTML)."""
    return (s.replace("&", "&amp;")
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
        ["Device", device.name],
        ["UID", device.device_uid],
        ["Owner", owner_email],
        ["OS", f"{os_info.get('system', '?')} {os_info.get('release', '')}".strip()],
        ["Hostname", os_info.get("hostname", "?")],
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

    sev_data = [["Severitate", "Număr"]]
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

    # ── Findings detaliate ──
    elements.append(PageBreak())
    elements.append(Paragraph("Vulnerabilități detectate", h2_style))
    elements.append(Spacer(1, 0.3 * cm))

    if not findings:
        elements.append(Paragraph(
            "<font color='#7a9a5a'>✓</font> Sistem curat — nicio vulnerabilitate detectată.",
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
        elements.append(Paragraph(
            f"<b>Durată:</b> {nmap.get('scan_time_sec', '?')}s · "
            f"{len(nmap['hosts'])} host-uri descoperite", small_style))
        elements.append(Spacer(1, 0.4 * cm))

        for host in nmap["hosts"]:
            ip = _escape_html(host.get("ip", "?"))
            hostname = _escape_html(host.get("hostname", "n/a"))
            elements.append(Paragraph(
                f"<b>{ip}</b> "
                f"<font size=9 color='{MUTED.hexval()}'>({hostname})</font>",
                body_style,
            ))
            if host.get("os_guess"):
                elements.append(Paragraph(
                    f"OS: {_escape_html(host['os_guess'])}", small_style))
            open_ports = [p for p in (host.get("ports") or []) if p.get("state") == "open"]
            if open_ports:
                ports_str = ", ".join(
                    f"{p.get('port')}/{p.get('proto', '?')} "
                    f"({p.get('service', '?')})"
                    for p in open_ports[:20]
                )
                elements.append(Paragraph(
                    f"Porturi open: {_escape_html(ports_str)}", small_style))
            vuln_findings = host.get("vulnwatch_findings") or []
            if vuln_findings:
                for vf in vuln_findings:
                    sev = (vf.get("severity") or "info").lower()
                    color = SEVERITY_COLOR.get(sev, MUTED)
                    elements.append(Paragraph(
                        f"<font color='{color.hexval()}'><b>[{sev.upper()}]</b></font> "
                        f"{_escape_html(vf.get('title', '?'))}",
                        small_style,
                    ))
            elements.append(Spacer(1, 0.35 * cm))

    # ── Footer ──
    elements.append(Spacer(1, 0.6 * cm))
    generated_at = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    elements.append(Paragraph(
        f"<font size=8 color='{MUTED.hexval()}'>"
        f"Generat de VulnWatch · {generated_at}</font>",
        small_style,
    ))

    doc.build(elements)
    return buf.getvalue()
