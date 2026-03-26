MITIGATION_KB = {
	"sql_injection": (
		"Use parameterized queries or prepared statements, prefer vetted ORM patterns, "
		"enforce strict input allowlists, and run DB accounts with least privilege."
	),
	"xss": (
		"Apply context-aware output encoding (for example, html.escape where appropriate), "
		"enforce a strong Content-Security-Policy, avoid innerHTML for untrusted data, "
		"and use textContent or safe templating APIs."
	),
	"input_validation": (
		"Implement server-side validation for all inputs, complement with HTML5 constraints "
		"(required, maxlength, pattern), ensure HTTPS form actions, and do not rely on hidden "
		"fields for security decisions."
	),
	"header_status": "Security header is present and appears correctly configured. No remediation needed.",
	"generic": "Review this finding and apply defence-in-depth principles.",
}

HEADER_MITIGATIONS = {
	"Content-Security-Policy": "Define a strict CSP and use nonces or hashes for script execution.",
	"X-Content-Type-Options": "Set X-Content-Type-Options to nosniff.",
	"X-Frame-Options": "Set X-Frame-Options to DENY or SAMEORIGIN; prefer CSP frame-ancestors where possible.",
	"Strict-Transport-Security": "Enable HSTS with max-age=31536000; includeSubDomains.",
	"X-XSS-Protection": "For legacy browser support, set X-XSS-Protection to 1; mode=block. For modern browsers, rely on CSP.",
	"Referrer-Policy": "Set Referrer-Policy to strict-origin-when-cross-origin.",
	"Permissions-Policy": "Restrict unused browser features with a least-privilege Permissions-Policy.",
	"Cache-Control": "Set Cache-Control to no-store for authenticated or sensitive content.",
}


class MitigationKB:
	def get_mitigation(self, finding: dict) -> str:
		finding_type = finding.get("type", "")
		evidence = str(finding.get("evidence", "")).lower()
		issue = str(finding.get("issue", "")).lower()
		method = str(finding.get("method", "")).lower()
		location = str(finding.get("location", "")).lower()

		if (
			(finding_type == "sql_injection" and (method == "none" or "no sql injection vulnerabilities detected" in evidence))
			or (finding_type == "xss" and (location == "none" or "no xss vulnerabilities detected" in evidence))
			or (finding_type == "input_validation" and "no form fields found to validate" in evidence)
			or (finding_type == "input_validation" and "no form fields found to validate" in issue)
		):
			return "No remediation needed. No vulnerabilities were detected for this check."

		if finding_type == "sql_injection":
			return MITIGATION_KB["sql_injection"]

		if finding_type == "xss":
			return MITIGATION_KB["xss"]

		if finding_type == "missing_header":
			header_name = finding.get("header")
			return HEADER_MITIGATIONS.get(header_name, MITIGATION_KB["generic"])

		if finding_type == "input_validation":
			return MITIGATION_KB["input_validation"]

		if finding_type == "header_status" and str(finding.get("status", "")).lower() == "present":
			return MITIGATION_KB["header_status"]

		return MITIGATION_KB["generic"]
