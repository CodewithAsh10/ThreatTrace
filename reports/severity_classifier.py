try:
	from ..config import SCORE_DEDUCTIONS, SEVERITY_LEVELS
except ImportError:
	from config import SCORE_DEDUCTIONS, SEVERITY_LEVELS


class SeverityClassifier:
	SEVERITY_MAP = {
		"xss": "MEDIUM",
		"input_validation": "LOW",
		"header_status": "INFO",
	}
	HIGH_IMPACT_HEADERS = {"Content-Security-Policy", "Strict-Transport-Security"}

	def classify(self, finding: dict) -> str:
		finding_type = finding.get("type", "")
		confidence = str(finding.get("confidence", "")).upper()
		status = str(finding.get("status", "")).lower()
		header = finding.get("header")
		evidence = str(finding.get("evidence", "")).lower()
		issue = str(finding.get("issue", "")).lower()
		method = str(finding.get("method", "")).lower()
		location = str(finding.get("location", "")).lower()

		if finding_type == "sql_injection":
			if method == "none" or "no sql injection vulnerabilities detected" in evidence:
				return "INFO"
			if confidence == "HIGH":
				return "HIGH"
			if confidence == "MEDIUM":
				return "MEDIUM"
			return "MEDIUM"

		if finding_type == "xss":
			if location == "none" or "no xss vulnerabilities detected" in evidence:
				return "INFO"

		if finding_type == "input_validation":
			if "no form fields found to validate" in evidence or "no form fields found to validate" in issue:
				return "INFO"

		if finding_type == "missing_header":
			if status == "missing":
				if header in self.HIGH_IMPACT_HEADERS:
					return "MEDIUM"
				return "LOW"
			if status == "misconfigured":
				return "LOW"

		if finding_type == "header_status" and status == "present":
			return "INFO"

		return self.SEVERITY_MAP.get(finding_type, "INFO")

	def calculate_score(self, findings: list[dict]) -> int:
		score = 100
		for finding in findings:
			severity = self.classify(finding)
			score -= SCORE_DEDUCTIONS.get(severity, 0)
		return max(0, score)

	def count_by_severity(self, findings: list[dict]) -> dict:
		counts = {level: 0 for level in SEVERITY_LEVELS}
		for finding in findings:
			severity = self.classify(finding)
			if severity not in counts:
				counts[severity] = 0
			counts[severity] += 1
		return counts
