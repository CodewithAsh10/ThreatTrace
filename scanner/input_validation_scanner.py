import logging
import urllib.parse

from bs4 import BeautifulSoup

try:
	from ..config import MAX_SCAN_TIME
except ImportError:
	from config import MAX_SCAN_TIME


class InputValidationScanner:
	def scan(self, url: str, crawl_data: dict, progress_callback=None) -> list[dict]:
		_ = logging
		_ = MAX_SCAN_TIME

		html_content = crawl_data.get("html", "")
		soup = BeautifulSoup(html_content, "html.parser")
		findings = []
		for form in soup.find_all("form"):
			findings.extend(self._analyse_form(form, url, progress_callback))

		deduped = {}
		for finding in findings:
			key = (
				finding.get("form_action"),
				finding.get("field_name"),
				finding.get("issue"),
			)
			deduped[key] = finding
		findings = list(deduped.values())

		if not findings:
			findings.append(
				{
					"type": "input_validation",
					"form_action": url,
					"field_name": "N/A",
					"issue": "No form fields found to validate",
				}
			)
		return findings

	def _analyse_form(self, form, base_url: str, progress_callback=None) -> list[dict]:
		findings = []
		action = form.get("action", "")
		form_action = urllib.parse.urljoin(base_url, action) if action else base_url

		if form_action.startswith("http://"):
			findings.append(
				{
					"type": "input_validation",
					"form_action": form_action,
					"field_name": None,
					"issue": "Form submits over insecure HTTP",
				}
			)

		for field in form.find_all(["input", "textarea", "select"]):
			field_name = field.get("name", "<unnamed>")
			tag_name = field.name.lower()
			field_type = (field.get("type") or "text").lower()
			had_issue = False

			if field_type == "hidden":
				issue_text = "Hidden field may be manipulable by client"
				findings.append(
					{
						"type": "input_validation",
						"form_action": form_action,
						"field_name": field_name,
						"issue": issue_text,
					}
				)
				had_issue = True
				if progress_callback is not None:
					progress_callback(
						{
							"type": "finding",
							"module": "Input Validation",
							"severity": "LOW",
							"request_sent": False,
							"payload_tested": False,
							"detail": f"Issue on field '{field_name}': {issue_text}",
							"log": f"⚠️ Input issue on '{field_name}': {issue_text}",
						}
					)

			if tag_name == "input" and not field.has_attr("type"):
				issue_text = "Input field is missing type attribute"
				findings.append(
					{
						"type": "input_validation",
						"form_action": form_action,
						"field_name": field_name,
						"issue": issue_text,
					}
				)
				had_issue = True
				if progress_callback is not None:
					progress_callback(
						{
							"type": "finding",
							"module": "Input Validation",
							"severity": "LOW",
							"request_sent": False,
							"payload_tested": False,
							"detail": f"Issue on field '{field_name}': {issue_text}",
							"log": f"⚠️ Input issue on '{field_name}': {issue_text}",
						}
					)

			if field_type not in {"hidden", "submit"} and not field.has_attr("required"):
				issue_text = "Field is missing required attribute"
				findings.append(
					{
						"type": "input_validation",
						"form_action": form_action,
						"field_name": field_name,
						"issue": issue_text,
					}
				)
				had_issue = True
				if progress_callback is not None:
					progress_callback(
						{
							"type": "finding",
							"module": "Input Validation",
							"severity": "LOW",
							"request_sent": False,
							"payload_tested": False,
							"detail": f"Issue on field '{field_name}': {issue_text}",
							"log": f"⚠️ Input issue on '{field_name}': {issue_text}",
						}
					)

			if (tag_name == "textarea" or (tag_name == "input" and field_type == "text")) and not field.has_attr("maxlength"):
				issue_text = "Field is missing maxlength attribute"
				findings.append(
					{
						"type": "input_validation",
						"form_action": form_action,
						"field_name": field_name,
						"issue": issue_text,
					}
				)
				had_issue = True
				if progress_callback is not None:
					progress_callback(
						{
							"type": "finding",
							"module": "Input Validation",
							"severity": "LOW",
							"request_sent": False,
							"payload_tested": False,
							"detail": f"Issue on field '{field_name}': {issue_text}",
							"log": f"⚠️ Input issue on '{field_name}': {issue_text}",
						}
					)

			if tag_name == "input" and field_type == "text" and not field.has_attr("pattern"):
				issue_text = "Text input is missing pattern attribute"
				findings.append(
					{
						"type": "input_validation",
						"form_action": form_action,
						"field_name": field_name,
						"issue": issue_text,
					}
				)
				had_issue = True
				if progress_callback is not None:
					progress_callback(
						{
							"type": "finding",
							"module": "Input Validation",
							"severity": "LOW",
							"request_sent": False,
							"payload_tested": False,
							"detail": f"Issue on field '{field_name}': {issue_text}",
							"log": f"⚠️ Input issue on '{field_name}': {issue_text}",
						}
					)

			if not had_issue and progress_callback is not None:
				progress_callback(
					{
						"type": "step",
						"event_subtype": "informational",
						"module": "Input Validation",
						"request_sent": False,
						"payload_tested": False,
						"detail": f"Field '{field_name}' checked",
						"log": f"✅ Field '{field_name}' OK",
					}
				)

		return findings
