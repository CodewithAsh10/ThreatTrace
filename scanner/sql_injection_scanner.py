import logging
import os
import time
import urllib.parse

import requests

try:
	from ..config import PAYLOADS_DIR, RATE_LIMIT_DELAY, REQUEST_TIMEOUT
except ImportError:
	from config import PAYLOADS_DIR, RATE_LIMIT_DELAY, REQUEST_TIMEOUT


class SQLInjectionScanner:
	DB_ERRORS = (
		"mysql_fetch",
		"SQL syntax",
		"ORA-",
		"PostgreSQL",
		"sqlite3",
		"Microsoft SQL",
		"ODBC Driver",
		"syntax error",
		"unclosed quotation",
		"pg_query",
		"Warning: mysql",
		"valid MySQL result",
		"MySqlClient",
		"com.mysql.jdbc",
		"Zend_Db",
		"PSQLException",
	)

	def __init__(self):
		payload_path = os.path.join(PAYLOADS_DIR, "sqli_payloads.txt")
		self.payloads = self._load_payloads(payload_path)

	def scan(
		self,
		url: str,
		crawl_data: dict,
		deadline: float | None = None,
		progress_callback=None,
	) -> list[dict]:
		findings = []
		findings.extend(
			self._test_url_params(
				url,
				crawl_data.get("params", {}),
				deadline,
				progress_callback,
			)
		)
		if not self._deadline_exceeded(deadline):
			findings.extend(self._test_forms(crawl_data.get("forms", []), deadline, progress_callback))

		deduped = {}
		for finding in findings:
			key = (finding.get("parameter"), finding.get("payload"))
			deduped[key] = finding

		if not deduped:
			deduped[("N/A", "N/A")] = {
				"type": "sql_injection",
				"parameter": "N/A",
				"payload": "N/A",
				"evidence": "No SQL injection vulnerabilities detected",
				"confidence": "Low",
				"method": "none",
			}
		return list(deduped.values())

	def _load_payloads(self, payload_path: str) -> list[str]:
		payloads = []
		try:
			with open(payload_path, "r", encoding="utf-8") as payload_file:
				for line in payload_file:
					payload = line.strip()
					if payload:
						payloads.append(payload)
		except OSError as exc:
			logging.warning("Failed to load SQLi payloads from %s: %s", payload_path, exc)
		return payloads

	def _test_url_params(
		self,
		url: str,
		params: dict,
		deadline: float | None = None,
		progress_callback=None,
	) -> list[dict]:
		findings = []
		if not params:
			return findings
		if self._deadline_exceeded(deadline):
			return findings

		try:
			baseline_response = requests.get(url, timeout=REQUEST_TIMEOUT, verify=False)
		except requests.exceptions.RequestException as exc:
			logging.warning("Failed to fetch SQLi baseline response for %s: %s", url, exc)
			return findings

		parsed_url = urllib.parse.urlparse(url)
		for param in params:
			if self._deadline_exceeded(deadline):
				break
			total = len(self.payloads)
			for i, payload in enumerate(self.payloads):
				if self._deadline_exceeded(deadline):
					break
				test_params = dict(params)
				test_params[param] = payload
				query = urllib.parse.urlencode(test_params)
				modified_url = urllib.parse.urlunparse(
					(
						parsed_url.scheme,
						parsed_url.netloc,
						parsed_url.path,
						parsed_url.params,
						query,
						parsed_url.fragment,
					)
				)

				try:
					response = requests.get(modified_url, timeout=REQUEST_TIMEOUT, verify=False)
					error_finding = self._check_error_based(response, payload, param)
					if error_finding:
						findings.append(error_finding)
						if progress_callback is not None:
							progress_callback(
								{
									"type": "finding",
									"module": "SQL Injection Scanner",
									"severity": "HIGH",
									"request_sent": False,
									"payload_tested": False,
									"detail": f"⚠️ Vulnerability found on param '{param}'!",
									"log": f"⚠️ FOUND: SQL Injection on param '{param}'",
								}
							)

					blind_finding = self._check_blind(baseline_response, response, param, payload)
					if blind_finding:
						findings.append(blind_finding)
						if progress_callback is not None:
							progress_callback(
								{
									"type": "finding",
									"module": "SQL Injection Scanner",
									"severity": "HIGH",
									"request_sent": False,
									"payload_tested": False,
									"detail": f"⚠️ Vulnerability found on param '{param}'!",
									"log": f"⚠️ FOUND: SQL Injection on param '{param}'",
								}
							)
				except requests.exceptions.RequestException as exc:
					logging.warning("SQLi URL parameter test failed for %s: %s", modified_url, exc)
				finally:
					if progress_callback is not None:
						progress_callback(
							{
								"type": "step",
								"event_subtype": "payload_attempt",
								"module": "SQL Injection Scanner",
								"detail": f"Testing param '{param}' with payload {i+1}/{total} — {payload[:40]}",
								"payload": payload,
								"request_sent": True,
								"payload_tested": True,
								"log": f"💉 Testing param '{param}' with: {payload[:50]}",
							}
						)
					if not self._deadline_exceeded(deadline):
						time.sleep(RATE_LIMIT_DELAY)

		return findings

	def _test_forms(
		self,
		forms: list[dict],
		deadline: float | None = None,
		progress_callback=None,
	) -> list[dict]:
		findings = []
		for form in forms:
			if self._deadline_exceeded(deadline):
				break
			action = form.get("action")
			method = form.get("method", "get").lower()
			fields = form.get("fields", [])

			baseline_data = {
				field.get("name"): field.get("value", "")
				for field in fields
				if field.get("name")
			}

			try:
				baseline_response = self._submit_form(action, method, baseline_data)
			except requests.exceptions.RequestException as exc:
				logging.warning("Failed to fetch SQLi baseline form response for %s: %s", action, exc)
				continue

			for field in fields:
				if self._deadline_exceeded(deadline):
					break
				field_name = field.get("name")
				field_type = (field.get("type") or "text").lower()
				if not field_name or field_type == "hidden":
					continue

				total = len(self.payloads)
				for i, payload in enumerate(self.payloads):
					if self._deadline_exceeded(deadline):
						break
					data = dict(baseline_data)
					data[field_name] = payload
					try:
						response = self._submit_form(action, method, data)
						error_finding = self._check_error_based(response, payload, field_name)
						if error_finding:
							findings.append(error_finding)
							if progress_callback is not None:
								progress_callback(
									{
										"type": "finding",
										"module": "SQL Injection Scanner",
										"severity": "HIGH",
										"request_sent": False,
										"payload_tested": False,
										"detail": f"⚠️ Vulnerability found on param '{field_name}'!",
										"log": f"⚠️ FOUND: SQL Injection on param '{field_name}'",
									}
								)

						blind_finding = self._check_blind(
							baseline_response, response, field_name, payload
						)
						if blind_finding:
							findings.append(blind_finding)
							if progress_callback is not None:
								progress_callback(
									{
										"type": "finding",
										"module": "SQL Injection Scanner",
										"severity": "HIGH",
										"request_sent": False,
										"payload_tested": False,
										"detail": f"⚠️ Vulnerability found on param '{field_name}'!",
										"log": f"⚠️ FOUND: SQL Injection on param '{field_name}'",
									}
								)
					except requests.exceptions.RequestException as exc:
						logging.warning(
							"SQLi form test failed for %s field %s: %s",
							action,
							field_name,
							exc,
						)
					finally:
						if progress_callback is not None:
							progress_callback(
								{
									"type": "step",
									"event_subtype": "payload_attempt",
									"module": "SQL Injection Scanner",
									"detail": f"Testing param '{field_name}' with payload {i+1}/{total} — {payload[:40]}",
									"payload": payload,
									"request_sent": True,
									"payload_tested": True,
									"log": f"💉 Testing param '{field_name}' with: {payload[:50]}",
								}
							)
						if not self._deadline_exceeded(deadline):
							time.sleep(RATE_LIMIT_DELAY)

		return findings

	def _submit_form(self, action: str, method: str, data: dict):
		if method == "post":
			return requests.post(action, data=data, timeout=REQUEST_TIMEOUT, verify=False)
		return requests.get(action, params=data, timeout=REQUEST_TIMEOUT, verify=False)

	def _check_error_based(self, response, payload: str, param: str) -> dict | None:
		body_lower = response.text.lower()
		for signature in self.DB_ERRORS:
			signature_lower = signature.lower()
			index = body_lower.find(signature_lower)
			if index != -1:
				evidence = self._extract_evidence(response.text, index)
				return {
					"type": "sql_injection",
					"parameter": param,
					"payload": payload,
					"evidence": evidence,
					"confidence": "HIGH",
					"method": "error-based",
				}
		return None

	def _check_blind(self, baseline, response, param: str, payload: str) -> dict | None:
		baseline_time = baseline.elapsed.total_seconds() if baseline and baseline.elapsed else 0
		response_time = response.elapsed.total_seconds() if response and response.elapsed else 0
		if response_time - baseline_time > 4:
			return {
				"type": "sql_injection",
				"parameter": param,
				"payload": payload,
				"evidence": f"Response time increased from {baseline_time:.2f}s to {response_time:.2f}s",
				"confidence": "HIGH",
				"method": "time-based blind",
			}

		baseline_len = len(baseline.text) if baseline and baseline.text is not None else 0
		response_len = len(response.text) if response and response.text is not None else 0
		if baseline_len > 0 and abs(response_len - baseline_len) > (0.2 * baseline_len):
			return {
				"type": "sql_injection",
				"parameter": param,
				"payload": payload,
				"evidence": f"Response length changed from {baseline_len} to {response_len}",
				"confidence": "MEDIUM",
				"method": "blind",
			}

		return None

	def _extract_evidence(self, text: str, index: int, window: int = 100) -> str:
		start = max(0, index - window)
		end = min(len(text), index + window)
		return text[start:end]

	def _deadline_exceeded(self, deadline: float | None) -> bool:
		return deadline is not None and time.monotonic() > deadline
