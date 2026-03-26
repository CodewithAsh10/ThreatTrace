from datetime import datetime
from io import BytesIO

from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import getSampleStyleSheet
from reportlab.platypus import HRFlowable, Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle


class PDFGenerator:
	SEVERITY_COLORS = {
		"HIGH": colors.HexColor("#FF4444"),
		"MEDIUM": colors.HexColor("#FF8C00"),
		"LOW": colors.HexColor("#FFD700"),
		"INFO": colors.HexColor("#4A90D9"),
	}

	def generate_pdf(self, scan_result: dict) -> bytes:
		buffer = BytesIO()
		doc = SimpleDocTemplate(
			buffer,
			pagesize=A4,
			leftMargin=36,
			rightMargin=36,
			topMargin=36,
			bottomMargin=54,
		)
		styles = getSampleStyleSheet()
		story = []

		story.append(Paragraph("VulnGuard Security Report", styles["Title"]))
		story.append(Paragraph("Shielded Assessment and Web Security Analysis", styles["BodyText"]))
		story.append(Spacer(1, 8))
		story.append(HRFlowable(width="100%", thickness=1, color=colors.grey))
		story.append(Spacer(1, 12))

		started_at = scan_result.get("started_at")
		completed_at = scan_result.get("completed_at")
		duration_seconds = scan_result.get("duration_seconds")
		if duration_seconds is not None:
			duration_seconds = int(duration_seconds)
			minutes, seconds = divmod(max(0, duration_seconds), 60)
			hours, minutes = divmod(minutes, 60)
			if hours > 0:
				duration_text = f"{hours}h {minutes}m {seconds}s"
			elif minutes > 0:
				duration_text = f"{minutes}m {seconds}s"
			else:
				duration_text = f"{seconds}s"
			duration_display = f"{duration_text} ({duration_seconds}s)"
		else:
			duration_text = self._format_duration(started_at, completed_at)
			duration_display = duration_text

		metadata_rows = [
			["Target URL", str(scan_result.get("url", "N/A"))],
			["Scan Type", str(scan_result.get("scan_type", "N/A"))],
			["Started At", str(started_at or "N/A")],
			["Completed At", str(completed_at or "N/A")],
			["Duration", duration_display],
			["Duration (s)", str(duration_seconds if duration_seconds is not None else "N/A")],
		]
		metadata_table = Table(metadata_rows, colWidths=[120, 390])
		metadata_table.setStyle(
			TableStyle(
				[
					("BACKGROUND", (0, 0), (0, -1), colors.whitesmoke),
					("FONTNAME", (0, 0), (0, -1), "Helvetica-Bold"),
					("GRID", (0, 0), (-1, -1), 0.5, colors.lightgrey),
					("VALIGN", (0, 0), (-1, -1), "TOP"),
				]
			)
		)
		story.append(metadata_table)
		story.append(Spacer(1, 16))

		raw_score = scan_result.get("score", 0)
		try:
			score = int(raw_score) if raw_score is not None else 0
		except (TypeError, ValueError):
			score = 0
		score_band = self._score_band(score)
		story.append(Paragraph(f"Overall Security Score: <b>{score}</b> ({score_band})", styles["Heading2"]))
		story.append(Spacer(1, 12))

		summary = scan_result.get("summary", {})
		summary_rows = [["Severity", "Count"]]
		for severity in ["HIGH", "MEDIUM", "LOW", "INFO", "total"]:
			label = severity.upper() if severity != "total" else "TOTAL"
			if severity == "total":
				count = summary.get("total", 0) or summary.get("TOTAL", 0)
			else:
				count = summary.get(severity, 0) or summary.get(severity.lower(), 0)
			summary_rows.append([label, str(count)])

		summary_table = Table(summary_rows, colWidths=[200, 80])
		summary_style = [
			("BACKGROUND", (0, 0), (-1, 0), colors.black),
			("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
			("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
			("GRID", (0, 0), (-1, -1), 0.5, colors.lightgrey),
			("ALIGN", (1, 1), (1, -1), "CENTER"),
		]
		summary_style.extend(
			[
				("BACKGROUND", (0, 1), (-1, 1), self.SEVERITY_COLORS["HIGH"]),
				("BACKGROUND", (0, 2), (-1, 2), self.SEVERITY_COLORS["MEDIUM"]),
				("BACKGROUND", (0, 3), (-1, 3), self.SEVERITY_COLORS["LOW"]),
				("BACKGROUND", (0, 4), (-1, 4), self.SEVERITY_COLORS["INFO"]),
				("BACKGROUND", (0, 5), (-1, 5), colors.whitesmoke),
			]
		)
		summary_table.setStyle(TableStyle(summary_style))
		story.append(Paragraph("Executive Summary", styles["Heading3"]))
		story.append(summary_table)
		story.append(Spacer(1, 16))

		story.append(Paragraph("Detailed Findings", styles["Heading3"]))
		findings = scan_result.get("findings", [])
		if not findings:
			story.append(Paragraph("No findings recorded.", styles["BodyText"]))
		else:
			SEVERITY_ORDER = {"HIGH": 0, "MEDIUM": 1, "LOW": 2, "INFO": 3}
			findings = sorted(
				findings,
				key=lambda f: SEVERITY_ORDER.get(str(f.get("severity", "INFO")).upper(), 4),
			)
			info_section_started = False
			for finding in findings:
				severity = str(finding.get("severity", "INFO")).upper()
				severity_color = self.SEVERITY_COLORS.get(severity, colors.whitesmoke)
				finding_type = str(finding.get("type", ""))
				parameter_or_header = (
					finding.get("parameter")
					or finding.get("header")
					or finding.get("field_name")
					or "N/A"
				)
				evidence = (
					finding.get("evidence")
					or finding.get("risk_description")
					or finding.get("issue")
					or "N/A"
				)
				mitigation = finding.get("mitigation") or "N/A"

				if severity == "INFO" and not info_section_started:
					info_section_started = True
					story.append(Spacer(1, 6))
					story.append(
						HRFlowable(width="100%", thickness=0.5, color=colors.lightgrey, dash=(2, 4))
					)
					story.append(Paragraph("Informational Findings", styles["Heading3"]))
					story.append(Spacer(1, 6))

				finding_rows = [
					["Type", Paragraph(finding_type, styles["BodyText"])],
					["Parameter/Header", Paragraph(str(parameter_or_header), styles["BodyText"])],
					["Severity", Paragraph(severity, styles["BodyText"])],
					["Evidence", Paragraph(str(evidence), styles["BodyText"])],
					["Mitigation", Paragraph(str(mitigation), styles["BodyText"])],
				]
				finding_table = Table(finding_rows, colWidths=[120, 390])
				finding_table.setStyle(
					TableStyle(
						[
							("BACKGROUND", (0, 0), (0, -1), colors.whitesmoke),
							("FONTNAME", (0, 0), (0, -1), "Helvetica-Bold"),
							("GRID", (0, 0), (-1, -1), 0.5, colors.lightgrey),
							("VALIGN", (0, 0), (-1, -1), "TOP"),
							("BACKGROUND", (1, 2), (1, 2), severity_color),
						]
					)
				)
				story.append(finding_table)
				story.append(Spacer(1, 10))

		generated_at = datetime.utcnow().isoformat()

		def _draw_footer(canvas, _doc):
			canvas.saveState()
			canvas.setFont("Helvetica", 8)
			canvas.drawString(36, 24, f"Generated by VulnGuard | Generated at {generated_at}")
			canvas.drawRightString(A4[0] - 36, 24, f"Page {canvas.getPageNumber()}")
			canvas.restoreState()

		doc.build(story, onFirstPage=_draw_footer, onLaterPages=_draw_footer)
		return buffer.getvalue()

	def _score_band(self, score: int) -> str:
		if score < 40:
			return "Critical"
		if score < 70:
			return "Needs Improvement"
		return "Good"

	def _parse_timestamp(self, value: str | None):
		if not value:
			return None
		normalized = str(value).replace("Z", "+00:00")
		try:
			return datetime.fromisoformat(normalized)
		except ValueError:
			return None

	def _format_duration(self, started_at: str | None, completed_at: str | None) -> str:
		start_dt = self._parse_timestamp(started_at)
		end_dt = self._parse_timestamp(completed_at)
		if not start_dt or not end_dt:
			return "N/A"

		duration_seconds = max(0, int((end_dt - start_dt).total_seconds()))
		minutes, seconds = divmod(duration_seconds, 60)
		hours, minutes = divmod(minutes, 60)
		if hours > 0:
			return f"{hours}h {minutes}m {seconds}s"
		if minutes > 0:
			return f"{minutes}m {seconds}s"
		return f"{seconds}s"
