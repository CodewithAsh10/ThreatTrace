import html
import logging
import os
import time
import urllib.parse

import requests

try:
	from ..config import PAYLOADS_DIR, RATE_LIMIT_DELAY, REQUEST_TIMEOUT
except ImportError:
	from config import PAYLOADS_DIR, RATE_LIMIT_DELAY, REQUEST_TIMEOUT


class XSSScanner:
	def __init__(self):
		payload_path = os.path.join(PAYLOADS_DIR, "xss_payloads.txt")
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
			key = (finding.get("parameter"), finding.get("location"))
			deduped[key] = finding

		if not deduped:
			deduped[("N/A", "N/A")] = {
				"type": "xss",
				"parameter": "N/A",
				"payload": "N/A",
				"location": "none",
				"evidence": "No XSS vulnerabilities detected",
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
			logging.warning("Failed to load XSS payloads from %s: %s", payload_path, exc)
		return payloads

	def _test_url_params(
		self,
		url: str,
		params: dict,
		deadline: float | None = None,
		progress_callback=None,
	) -> list[dict]:
		findings = []
		parsed_url = urllib.parse.urlparse(url)
		if self._deadline_exceeded(deadline):
			return findings

		for param in params:
			if self._deadline_exceeded(deadline):
				break
			param_confirmed_vulnerable = False
			for payload in self.payloads:
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
					finding = self._check_reflection(
						response.text, payload, param, "url_parameter"
					)
					if finding:
						findings.append(finding)
						param_confirmed_vulnerable = True
						if progress_callback is not None:
							progress_callback(
								{
									"type": "finding",
									"module": "XSS Scanner",
									"severity": "HIGH",
									"request_sent": False,
									"payload_tested": False,
									"detail": f"⚠️ XSS reflected on param '{param}'!",
									"log": f"⚠️ FOUND: XSS on param '{param}'",
								}
							)
				except requests.exceptions.RequestException as exc:
					logging.warning("XSS URL parameter test failed for %s: %s", modified_url, exc)
				finally:
					if progress_callback is not None:
						progress_callback(
							{
								"type": "step",
								"event_subtype": "payload_attempt",
								"module": "XSS Scanner",
								"detail": f"Testing param '{param}' with: {payload[:40]}",
								"payload": payload,
								"request_sent": True,
								"payload_tested": True,
								"log": f"💉 XSS probe on '{param}': {payload[:50]}",
							}
						)
					if not self._deadline_exceeded(deadline):
						time.sleep(RATE_LIMIT_DELAY)

				if param_confirmed_vulnerable:
					break

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

			for field in fields:
				if self._deadline_exceeded(deadline):
					break
				field_name = field.get("name")
				field_type = (field.get("type") or "text").lower()
				if not field_name or field_type in {"hidden", "submit"}:
					continue
				field_confirmed_vulnerable = False

				for payload in self.payloads:
					if self._deadline_exceeded(deadline):
						break
					data = dict(baseline_data)
					data[field_name] = payload
					try:
						response = self._submit_form(action, method, data)
						finding = self._check_reflection(
							response.text,
							payload,
							field_name,
							"form_field",
						)
						if finding:
							findings.append(finding)
							field_confirmed_vulnerable = True
							if progress_callback is not None:
								progress_callback(
									{
										"type": "finding",
										"module": "XSS Scanner",
										"severity": "HIGH",
										"request_sent": False,
										"payload_tested": False,
										"detail": f"⚠️ XSS reflected on param '{field_name}'!",
										"log": f"⚠️ FOUND: XSS on param '{field_name}'",
									}
								)
					except requests.exceptions.RequestException as exc:
						logging.warning(
							"XSS form test failed for %s field %s: %s",
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
									"module": "XSS Scanner",
									"detail": f"Testing param '{field_name}' with: {payload[:40]}",
									"payload": payload,
									"request_sent": True,
									"payload_tested": True,
									"log": f"💉 XSS probe on '{field_name}': {payload[:50]}",
								}
							)
						if not self._deadline_exceeded(deadline):
							time.sleep(RATE_LIMIT_DELAY)

						if field_confirmed_vulnerable:
							break

		return findings

	def _submit_form(self, action: str, method: str, data: dict):
		if method == "post":
			return requests.post(action, data=data, timeout=REQUEST_TIMEOUT, verify=False)
		return requests.get(action, params=data, timeout=REQUEST_TIMEOUT, verify=False)

	def _check_reflection(
		self, html_text: str, payload: str, parameter: str, location: str
	) -> dict | None:
		if payload not in html_text:
			return None

		escaped_payload = html.escape(payload)
		if escaped_payload in html_text and payload not in html_text:
			return None

		index = html_text.find(payload)
		snippet_start = max(0, index - 25)
		snippet_end = min(len(html_text), index + 25)
		evidence = html_text[snippet_start:snippet_end]
		return {
			"type": "xss",
			"parameter": parameter,
			"payload": payload,
			"location": location,
			"evidence": evidence,
		}

	def _deadline_exceeded(self, deadline: float | None) -> bool:
		return deadline is not None and time.monotonic() > deadline
