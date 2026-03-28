from datetime import datetime, timezone

from .mitigation_kb import MitigationKB
from .severity_classifier import SeverityClassifier


class ReportGenerator:
	TYPE_DISPLAY_MAP = {
		"sql_injection": "SQL Injection",
		"xss": "XSS",
		"missing_header": "Missing Security Header",
		"header_status": "Security Header",
		"input_validation": "Input Validation",
	}

	def __init__(self):
		self.classifier = SeverityClassifier()
		self.kb = MitigationKB()

	def _utc_now_iso(self) -> str:
		return datetime.now(timezone.utc).isoformat()

	def _parse_iso_utc(self, value: str | None) -> datetime | None:
		if not value:
			return None
		try:
			raw = str(value).strip()
			if not raw:
				return None
			if raw.endswith("Z"):
				raw = f"{raw[:-1]}+00:00"
			dt = datetime.fromisoformat(raw)
			if dt.tzinfo is None:
				dt = dt.replace(tzinfo=timezone.utc)
			return dt.astimezone(timezone.utc)
		except (TypeError, ValueError):
			return None

	def _normalise_finding(self, finding: dict, scan_url: str) -> dict:
		normalised = dict(finding)
		normalised["type"] = normalised.get("type", "unknown")
		normalised["parameter"] = (
			normalised.get("parameter")
			or normalised.get("header")
			or normalised.get("field_name")
			or "N/A"
		)
		normalised["evidence"] = (
			normalised.get("evidence")
			or normalised.get("risk_description")
			or normalised.get("issue")
			or "N/A"
		)
		normalised["url"] = normalised.get("url") or normalised.get("form_action") or scan_url
		normalised["payload"] = normalised.get("payload") or "N/A"
		normalised["confidence"] = normalised.get("confidence") or "Medium"
		return normalised

	def generate(
		self,
		scan_meta: dict,
		sqli_findings: list,
		xss_findings: list,
		header_findings: list,
		input_findings: list,
	) -> dict:
		SEVERITY_ORDER = {"HIGH": 0, "MEDIUM": 1, "LOW": 2, "INFO": 3}

		all_findings = list(sqli_findings) + list(xss_findings) + list(header_findings) + list(input_findings)
		completed_at = self._utc_now_iso()

		duration_seconds = 0
		try:
			started_dt = self._parse_iso_utc(scan_meta.get("started_at"))
			completed_dt = self._parse_iso_utc(completed_at)
			if started_dt is None or completed_dt is None:
				raise ValueError("Invalid timestamp")
			duration_seconds = int((completed_dt - started_dt).total_seconds())
		except (KeyError, TypeError, ValueError):
			duration_seconds = 0

		enriched_findings = []
		for finding in all_findings:
			enriched = self._normalise_finding(dict(finding), scan_meta["url"])
			enriched["severity"] = self.classifier.classify(enriched)
			enriched["mitigation"] = self.kb.get_mitigation(enriched)
			enriched_findings.append(enriched)

		score = self.classifier.calculate_score(enriched_findings)
		summary = self.classifier.count_by_severity(enriched_findings)

		api_findings = []
		for finding in enriched_findings:
			api_finding = dict(finding)
			raw_type = api_finding.get("type", "unknown")
			api_finding["raw_type"] = raw_type
			api_finding["type"] = self.TYPE_DISPLAY_MAP.get(raw_type, raw_type)
			api_findings.append(api_finding)

		api_findings.sort(
			key=lambda finding: SEVERITY_ORDER.get(str(finding.get("severity", "")).upper(), 4)
		)

		return {
			"scan_id": scan_meta["scan_id"],
			"url": scan_meta["url"],
			"scan_type": scan_meta["scan_type"],
			"started_at": scan_meta["started_at"],
			"completed_at": completed_at,
			"duration_seconds": duration_seconds,
			"status": "completed",
			"score": score,
			"summary": {
				"HIGH": summary.get("HIGH", 0),
				"MEDIUM": summary.get("MEDIUM", 0),
				"LOW": summary.get("LOW", 0),
				"INFO": summary.get("INFO", 0),
				"total": len(enriched_findings),
			},
			"findings": api_findings,
		}
