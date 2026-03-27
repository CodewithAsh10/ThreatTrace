import logging

import requests

try:
	from ..config import REQUEST_TIMEOUT
except ImportError:
	from config import REQUEST_TIMEOUT


class HeaderScanner:
	HEADER_RULES = {
		"Content-Security-Policy": {
			"required_value": None,
			"risk_description": "Missing CSP may allow script injection and content loading attacks.",
			"misconfigured_description": "Content-Security-Policy is present but appears misconfigured.",
		},
		"X-Content-Type-Options": {
			"required_value": ["nosniff"],
			"risk_description": "Missing X-Content-Type-Options may allow MIME-sniffing attacks.",
			"misconfigured_description": "X-Content-Type-Options should be set to nosniff.",
		},
		"X-Frame-Options": {
			"required_value": ["DENY", "SAMEORIGIN"],
			"risk_description": "Missing X-Frame-Options can expose the site to clickjacking.",
			"misconfigured_description": "X-Frame-Options should be DENY or SAMEORIGIN.",
		},
		"Strict-Transport-Security": {
			"required_value": None,
			"risk_description": "Missing HSTS can allow downgrade attacks over insecure transport.",
			"misconfigured_description": "Strict-Transport-Security is present but appears misconfigured.",
		},
		"X-XSS-Protection": {
			"required_value": None,
			"risk_description": "Missing X-XSS-Protection may reduce browser-level XSS mitigation.",
			"misconfigured_description": "X-XSS-Protection is present but appears misconfigured.",
		},
		"Referrer-Policy": {
			"required_value": None,
			"risk_description": "Missing Referrer-Policy may leak sensitive URL data to third parties.",
			"misconfigured_description": "Referrer-Policy is present but appears misconfigured.",
		},
		"Permissions-Policy": {
			"required_value": None,
			"risk_description": "Missing Permissions-Policy may expose browser capabilities unnecessarily.",
			"misconfigured_description": "Permissions-Policy is present but appears misconfigured.",
		},
		"Cache-Control": {
			"required_value": None,
			"risk_description": "Missing Cache-Control may allow sensitive pages to be cached.",
			"misconfigured_description": "Cache-Control is present but appears misconfigured.",
		},
	}

	def scan(self, url: str, crawl_data: dict, progress_callback=None) -> list[dict]:
		_ = requests
		_ = REQUEST_TIMEOUT
		_ = logging
		_ = url

		findings = []
		raw_headers = crawl_data.get("headers", {})
		headers = {str(key).lower(): str(value) for key, value in raw_headers.items()}

		for header_name, rule in self.HEADER_RULES.items():
			key = header_name.lower()
			actual_value = headers.get(key)
			required_values = rule.get("required_value")

			if actual_value is None:
				findings.append(
					{
						"type": "missing_header",
						"header": header_name,
						"status": "missing",
						"risk_description": rule.get("risk_description", ""),
						"actual_value": None,
					}
				)
				if progress_callback is not None:
					progress_callback(
						{
							"type": "finding",
							"module": "Security Headers",
							"severity": "MEDIUM",
							"request_sent": False,
							"payload_tested": False,
							"detail": f"Missing header: {header_name}",
							"log": f"🛡️ Missing: {header_name}",
						}
					)
				continue

			if required_values:
				normalized_actual = actual_value.strip().upper()
				normalized_expected = {value.upper() for value in required_values}
				if normalized_actual not in normalized_expected:
					findings.append(
						{
							"type": "missing_header",
							"header": header_name,
							"status": "misconfigured",
							"risk_description": rule.get("misconfigured_description", ""),
							"actual_value": actual_value,
						}
					)
					if progress_callback is not None:
						progress_callback(
							{
								"type": "finding",
								"module": "Security Headers",
								"severity": "MEDIUM",
								"request_sent": False,
								"payload_tested": False,
								"detail": f"Missing header: {header_name}",
								"log": f"🛡️ Missing: {header_name}",
							}
						)
					continue

			findings.append(
				{
					"type": "header_status",
					"header": header_name,
					"status": "present",
					"risk_description": "",
					"actual_value": actual_value,
				}
			)
			if progress_callback is not None:
				progress_callback(
					{
						"type": "step",
						"event_subtype": "informational",
						"module": "Security Headers",
						"request_sent": False,
						"payload_tested": False,
						"detail": f"✅ {header_name} present",
						"log": f"✅ {header_name} OK",
					}
				)


		if not findings:
			findings.append(
				{
					"type": "header_status",
					"header": "N/A",
					"status": "present",
					"risk_description": "No headers were available to analyse",
					"actual_value": None,
				}
			)

		return findings
