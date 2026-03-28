from datetime import datetime, timezone
from io import BytesIO
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import getSampleStyleSheet
from reportlab.platypus import (
	HRFlowable,
	PageBreak,
	Paragraph,
	SimpleDocTemplate,
	Spacer,
	Table,
	TableStyle,
)


class PDFGenerator:
	SEVERITY_COLORS = {
		"HIGH": colors.HexColor("#FF4444"),
		"MEDIUM": colors.HexColor("#FF8C00"),
		"LOW": colors.HexColor("#FFD700"),
		"INFO": colors.HexColor("#4A90D9"),
	}

	def generate_pdf(self, scan_result: dict, client_timezone: str | None = None) -> bytes:
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
		tz = self._resolve_tz(client_timezone)

		started_at = scan_result.get("started_at")
		completed_at = scan_result.get("completed_at")
		raw_score = scan_result.get("score", 0)
		try:
			score = int(raw_score) if raw_score is not None else 0
		except (TypeError, ValueError):
			score = 0
		score_band = self._score_band(score)
		score_band_to_severity = {
			"Critical": "HIGH",
			"Needs Improvement": "MEDIUM",
			"Good": "LOW",
		}
		score_badge_color = self.SEVERITY_COLORS.get(
			score_band_to_severity.get(score_band, "INFO"),
			self.SEVERITY_COLORS["INFO"],
		)
		score_badge_hex = "#{:02X}{:02X}{:02X}".format(
			int(score_badge_color.red * 255),
			int(score_badge_color.green * 255),
			int(score_badge_color.blue * 255),
		)

		summary = scan_result.get("summary", {})
		findings = scan_result.get("findings", [])
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

		generated_at = datetime.utcnow().isoformat()

		story = []

		# Page 1 - Cover
		story.append(Paragraph("ThreatTrace", styles["Title"]))
		story.append(Paragraph("Security Assessment Report", styles["Heading2"]))
		story.append(Spacer(1, 8))
		story.append(HRFlowable(width="100%", thickness=1, color=colors.grey))
		story.append(Spacer(1, 12))
		story.append(Paragraph(f"Target URL: {str(scan_result.get('url', 'N/A'))}", styles["BodyText"]))
		story.append(
			Paragraph(
				f"Scan Date: {self._format_ts(started_at, tz)}",
				styles["BodyText"],
			)
		)
		story.append(Spacer(1, 14))

		score_badge = Table([[f"Security Score: {score}"]], colWidths=[180])
		score_badge.setStyle(
			TableStyle(
				[
					("BACKGROUND", (0, 0), (-1, -1), score_badge_color),
					("TEXTCOLOR", (0, 0), (-1, -1), colors.white),
					("ALIGN", (0, 0), (-1, -1), "CENTER"),
					("FONTNAME", (0, 0), (-1, -1), "Helvetica-Bold"),
					("FONTSIZE", (0, 0), (-1, -1), 14),
					("TOPPADDING", (0, 0), (-1, -1), 8),
					("BOTTOMPADDING", (0, 0), (-1, -1), 8),
				]
			)
		)
		story.append(score_badge)

		scanned_url = str(scan_result.get("url", "N/A"))
		duration_str = self._format_duration(started_at, completed_at)
		stats = scan_result.get("stats", {}) or {}
		payloads_tested = stats.get("payloads_tested", len(findings))
		requests_sent = stats.get("requests_sent", 0)
		total_findings = summary.get("total", 0) or summary.get("TOTAL", 0)
		high_count = summary.get("HIGH", 0) or summary.get("high", 0)
		medium_count = summary.get("MEDIUM", 0) or summary.get("medium", 0)
		low_count = summary.get("LOW", 0) or summary.get("low", 0)
		info_count = summary.get("INFO", 0) or summary.get("info", 0)
		if score >= 70:
			band_label = "Secure"
			band_emoji = "✅"
		elif score >= 40:
			band_label = "Moderate Risk"
			band_emoji = "⚠️"
		else:
			band_label = "High Risk"
			band_emoji = "🚨"
		narrative_text = (
			f"We scanned {scanned_url} and tested {payloads_tested} payloads across 4 security modules in {duration_str}. "
			f"We sent {requests_sent} requests to analyze your website's security posture. "
			f"We found {total_findings} vulnerabilities: {high_count} High Risk, {medium_count} Medium Risk, {low_count} Low Risk, "
			f"and {info_count} Informational finding(s). Your security score is {score}/100 — {band_label} {band_emoji}."
		)
		story.append(Spacer(1, 14))
		story.append(Paragraph(narrative_text, styles["BodyText"]))
		story.append(PageBreak())

		# Page 2 - Executive Summary
		story.append(Paragraph("Executive Summary", styles["Heading1"]))
		story.append(Spacer(1, 12))
		story.append(
			Paragraph(
				f"Overall Security Score: {score} / 100 - {score_band}",
				styles["Heading2"],
			)
		)
		story.append(Spacer(1, 12))
		story.append(summary_table)
		story.append(Spacer(1, 10))
		story.append(
			Paragraph(
				f"<b><font color='{score_badge_hex}'>{score_band}</font></b>",
				styles["BodyText"],
			)
		)
		story.append(PageBreak())

		# Page 3 - Detailed Findings
		story.append(Paragraph("Detailed Findings", styles["Heading1"]))
		story.append(Spacer(1, 16))
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

		story.append(PageBreak())

		# Page 4 - Disclaimer / Footer
		story.append(Paragraph("Disclaimer", styles["Heading2"]))
		story.append(Spacer(1, 10))
		story.append(
			Paragraph(
				"This report was generated automatically by ThreatTrace. The findings represent "
				"the state of the target at the time of scanning and may not reflect all "
				"vulnerabilities present. This report is intended for authorised personnel only.",
				styles["BodyText"],
			)
		)
		story.append(Spacer(1, 14))

		disclaimer_metadata_rows = [
			["Generated At", self._format_ts(generated_at, tz)],
			["Scan ID", str(scan_result.get("scan_id", "N/A"))],
			["Target URL", str(scan_result.get("url", "N/A"))],
			["Scan Type", str(scan_result.get("scan_type", "N/A"))],
			["Started At", self._format_ts(started_at, tz)],
			["Completed At", self._format_ts(completed_at, tz)],
		]
		disclaimer_metadata_table = Table(disclaimer_metadata_rows, colWidths=[120, 390])
		disclaimer_metadata_table.setStyle(
			TableStyle(
				[
					("BACKGROUND", (0, 0), (0, -1), colors.whitesmoke),
					("FONTNAME", (0, 0), (0, -1), "Helvetica-Bold"),
					("GRID", (0, 0), (-1, -1), 0.5, colors.lightgrey),
					("VALIGN", (0, 0), (-1, -1), "TOP"),
				]
			)
		)
		story.append(disclaimer_metadata_table)

		def _draw_footer(canvas, _doc):
			canvas.saveState()
			canvas.setFont("Helvetica", 8)
			canvas.drawString(36, 24, f"Generated by ThreatTrace | Generated at {generated_at}")
			canvas.drawRightString(A4[0] - 36, 24, f"Page {canvas.getPageNumber()}")
			canvas.restoreState()

		def _draw_cover_page(canvas, _doc):
			canvas.saveState()
			canvas.translate(A4[0] / 2, A4[1] / 2)
			canvas.rotate(45)
			canvas.setFont("Helvetica-Bold", 72)
			canvas.setFillAlpha(0.08)
			canvas.setFillColorRGB(0.5, 0.5, 0.5)
			canvas.drawCentredString(0, 0, "CONFIDENTIAL")
			canvas.restoreState()
			_draw_footer(canvas, _doc)

		doc.build(story, onFirstPage=_draw_cover_page, onLaterPages=_draw_footer)
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

	def _resolve_tz(self, tz_name):
		if not tz_name:
			return timezone.utc
		try:
			return ZoneInfo(str(tz_name))
		except ZoneInfoNotFoundError:
			return timezone.utc

	def _format_ts(self, iso_str, tz) -> str:
		if iso_str is None:
			return "N/A"

		# Support epoch timestamps provided as numbers or numeric strings.
		epoch_value = None
		if isinstance(iso_str, (int, float)):
			epoch_value = float(iso_str)
		elif isinstance(iso_str, str):
			value = iso_str.strip()
			if value:
				try:
					epoch_value = float(value)
				except ValueError:
					epoch_value = None

		if epoch_value is not None:
			try:
				dt = datetime.fromtimestamp(epoch_value, tz=tz)
				return dt.strftime("%Y-%m-%d %H:%M:%S %Z")
			except (OverflowError, OSError, ValueError):
				return "N/A"

		dt = self._parse_timestamp(iso_str)
		if not dt:
			return "N/A"
		if dt.tzinfo is None:
			dt = dt.replace(tzinfo=timezone.utc)
		return dt.astimezone(tz).strftime("%Y-%m-%d %H:%M:%S %Z")

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
