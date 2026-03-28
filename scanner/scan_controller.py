import logging
import threading
import time
import uuid
from datetime import datetime

try:
	from ..config import MAX_SCAN_TIME
	from ..reports import ReportGenerator
	from ..storage import ScanStore
	from . import (
		Crawler,
		HeaderScanner,
		InputValidationScanner,
		SQLInjectionScanner,
		XSSScanner,
	)
except ImportError:
	from config import MAX_SCAN_TIME
	from reports import ReportGenerator
	from scanner import (
		Crawler,
		HeaderScanner,
		InputValidationScanner,
		SQLInjectionScanner,
		XSSScanner,
	)
	from storage import ScanStore


class ScanController:
	def __init__(self, scan_store: ScanStore):
		self.scan_store = scan_store
		self.report_generator = ReportGenerator()

	def start_scan(
		self,
		scan_id: str,
		url: str,
		scan_type: str,
		client_timezone: str | None = None,
	) -> None:
		if not scan_id:
			scan_id = str(uuid.uuid4())

		record = {
			"scan_id": scan_id,
			"url": url,
			"scan_type": scan_type,
			"client_timezone": client_timezone,
			"status": "queued",
			"started_at": datetime.utcnow().isoformat(),
			"completed_at": None,
			"progress": 0,
			"current_module": "Queued",
			"results": None,
			"score": None,
			"progress_log": [],
			"pending_findings": [],
			"modules": [
				{"name": "Page Crawler", "status": "pending", "details": "Waiting..."},
				{"name": "SQL Injection", "status": "pending", "details": "Waiting..."},
				{"name": "XSS Scanner", "status": "pending", "details": "Waiting..."},
				{"name": "Security Headers", "status": "pending", "details": "Waiting..."},
				{"name": "Input Validation", "status": "pending", "details": "Waiting..."},
				{"name": "Report Generation", "status": "pending", "details": "Waiting..."},
			],
			"stats": {
				"requests_sent": 0,
				"payloads_tested": 0,
				"vulnerabilities_found": 0,
				"elapsed_seconds": 0,
			},
		}
		self.scan_store.save_scan(scan_id, record)
		thread = threading.Thread(target=self._run, args=(scan_id, url, scan_type), daemon=True)
		thread.start()

	def _run(self, scan_id: str, url: str, scan_type: str) -> None:
		deadline = time.monotonic() + MAX_SCAN_TIME
		scan_start_time = time.monotonic()
		sqli_findings = []
		xss_findings = []
		header_findings = []
		input_findings = []
		crawl_data = {
			"url": url,
			"status_code": None,
			"headers": {},
			"html": "",
			"forms": [],
			"params": {},
			"response": None,
			"error": None,
		}

		current_record = self.scan_store.get_scan(scan_id) or {}
		current_modules = list(current_record.get("modules") or [])
		current_stats = dict(
			current_record.get("stats")
			or {
				"requests_sent": 0,
				"payloads_tested": 0,
				"vulnerabilities_found": 0,
				"elapsed_seconds": 0,
			}
		)

		def _make_callback(module_index, module_name):
			def _callback(event: dict):
				event = event or {}
				event_type = event.get("type", "step")
				request_sent = bool(event.get("request_sent", False))
				payload_tested = bool(event.get("payload_tested", False))
				message = event.get("log", "")
				if event_type == "finding":
					icon = "⚠️"
				elif message.startswith("✅"):
					icon = "✅"
				elif message.startswith("💉"):
					icon = "💉"
				elif message.startswith("🛡️"):
					icon = "🛡️"
				else:
					icon = "ℹ️"

				if module_index < len(current_modules):
					current_modules[module_index]["details"] = event.get("detail", "")

				if event_type == "finding":
					current_stats["vulnerabilities_found"] = current_stats.get("vulnerabilities_found", 0) + 1

				if payload_tested:
					current_stats["payloads_tested"] = current_stats.get("payloads_tested", 0) + 1

				if request_sent:
					current_stats["requests_sent"] = current_stats.get("requests_sent", 0) + 1

				current_stats["elapsed_seconds"] = int(time.monotonic() - scan_start_time)

				log_entry = {
					"timestamp": f"{datetime.utcnow().strftime('%H:%M:%S')} UTC",
					"icon": icon,
					"message": message,
				}

				finding_event = None
				if event_type == "finding":
					finding_event = {
						"timestamp": f"{datetime.utcnow().strftime('%H:%M:%S')} UTC",
						"module": event.get("module", module_name),
						"severity": event.get("severity", "INFO"),
						"detail": event.get("detail", ""),
						"message": message,
					}

				self.scan_store.update_scan_progress(
					scan_id,
					modules=current_modules,
					stats=current_stats,
					log_entry=log_entry,
					finding=finding_event,
				)

			return _callback

		self.scan_store.update_scan_progress(scan_id, modules=current_modules, stats=current_stats)

		try:
			crawler = Crawler()
			if len(current_modules) > 0:
				current_modules[0]["status"] = "running"
				current_modules[0]["details"] = "Crawling target page"
				self.scan_store.update_scan_progress(scan_id, modules=current_modules, stats=current_stats)
			succeeded, crawl_result = self._execute_with_deadline(
				lambda: crawler.crawl(url),
				deadline,
				"Crawler",
			)
			if not succeeded:
				self._mark_timeout(
					scan_id,
					"Crawler",
					sqli_findings,
					xss_findings,
					header_findings,
					input_findings,
				)
				return
			crawl_data = crawl_result
			if len(current_modules) > 0:
				forms_count = len(crawl_data.get("forms", []))
				params_count = len(crawl_data.get("params", {}))
				current_modules[0]["status"] = "completed"
				current_modules[0]["details"] = f"Found {forms_count} forms, {params_count} params"
				self.scan_store.update_scan_progress(scan_id, modules=current_modules, stats=current_stats)
			self.scan_store.update_progress(scan_id, 10, "Crawler", "in-progress")
			time.sleep(1)
			if time.monotonic() > deadline:
				self._mark_timeout(
					scan_id,
					"Crawler",
					sqli_findings,
					xss_findings,
					header_findings,
					input_findings,
				)
				return

			sqli_scanner = SQLInjectionScanner()
			if len(current_modules) > 1:
				current_modules[1]["status"] = "running"
				current_modules[1]["details"] = "Testing SQL injection payloads"
				self.scan_store.update_scan_progress(scan_id, modules=current_modules, stats=current_stats)
			succeeded, sqli_result = self._execute_with_deadline(
				lambda: sqli_scanner.scan(
					url,
					crawl_data,
					deadline=deadline,
					progress_callback=_make_callback(1, "SQL Injection"),
				),
				deadline,
				"SQL Injection Scanner",
			)
			if not succeeded:
				self._mark_timeout(
					scan_id,
					"SQL Injection Scanner",
					sqli_findings,
					xss_findings,
					header_findings,
					input_findings,
				)
				return
			sqli_findings = sqli_result
			if len(current_modules) > 1:
				current_modules[1]["status"] = "completed"
				self.scan_store.update_scan_progress(scan_id, modules=current_modules, stats=current_stats)
			self.scan_store.update_progress(scan_id, 25, "SQL Injection Scanner", "in-progress")
			time.sleep(2)
			if time.monotonic() > deadline:
				self._mark_timeout(
					scan_id,
					"SQL Injection Scanner",
					sqli_findings,
					xss_findings,
					header_findings,
					input_findings,
				)
				return

			xss_scanner = XSSScanner()
			if len(current_modules) > 2:
				current_modules[2]["status"] = "running"
				current_modules[2]["details"] = "Testing XSS payloads"
				self.scan_store.update_scan_progress(scan_id, modules=current_modules, stats=current_stats)
			succeeded, xss_result = self._execute_with_deadline(
				lambda: xss_scanner.scan(
					url,
					crawl_data,
					deadline=deadline,
					progress_callback=_make_callback(2, "XSS Scanner"),
				),
				deadline,
				"XSS Scanner",
			)
			if not succeeded:
				self._mark_timeout(
					scan_id,
					"XSS Scanner",
					sqli_findings,
					xss_findings,
					header_findings,
					input_findings,
				)
				return
			xss_findings = xss_result
			if len(current_modules) > 2:
				current_modules[2]["status"] = "completed"
				self.scan_store.update_scan_progress(scan_id, modules=current_modules, stats=current_stats)
			self.scan_store.update_progress(scan_id, 50, "XSS Scanner", "in-progress")
			time.sleep(2)
			if time.monotonic() > deadline:
				self._mark_timeout(
					scan_id,
					"XSS Scanner",
					sqli_findings,
					xss_findings,
					header_findings,
					input_findings,
				)
				return

			header_scanner = HeaderScanner()
			if len(current_modules) > 3:
				current_modules[3]["status"] = "running"
				current_modules[3]["details"] = "Checking security headers"
				self.scan_store.update_scan_progress(scan_id, modules=current_modules, stats=current_stats)
			succeeded, header_result = self._execute_with_deadline(
				lambda: header_scanner.scan(
					url,
					crawl_data,
					progress_callback=_make_callback(3, "Security Headers"),
				),
				deadline,
				"Header Analyzer",
			)
			if not succeeded:
				self._mark_timeout(
					scan_id,
					"Header Analyzer",
					sqli_findings,
					xss_findings,
					header_findings,
					input_findings,
				)
				return
			header_findings = header_result
			if len(current_modules) > 3:
				current_modules[3]["status"] = "completed"
				self.scan_store.update_scan_progress(scan_id, modules=current_modules, stats=current_stats)
			self.scan_store.update_progress(scan_id, 75, "Header Analyzer", "in-progress")
			time.sleep(1)
			if time.monotonic() > deadline:
				self._mark_timeout(
					scan_id,
					"Header Analyzer",
					sqli_findings,
					xss_findings,
					header_findings,
					input_findings,
				)
				return

			input_scanner = InputValidationScanner()
			if len(current_modules) > 4:
				current_modules[4]["status"] = "running"
				current_modules[4]["details"] = "Validating form fields"
				self.scan_store.update_scan_progress(scan_id, modules=current_modules, stats=current_stats)
			succeeded, input_result = self._execute_with_deadline(
				lambda: input_scanner.scan(
					url,
					crawl_data,
					progress_callback=_make_callback(4, "Input Validation"),
				),
				deadline,
				"Input Validation Scanner",
			)
			if not succeeded:
				self._mark_timeout(
					scan_id,
					"Input Validation Scanner",
					sqli_findings,
					xss_findings,
					header_findings,
					input_findings,
				)
				return
			input_findings = input_result
			if len(current_modules) > 4:
				current_modules[4]["status"] = "completed"
				self.scan_store.update_scan_progress(scan_id, modules=current_modules, stats=current_stats)
			self.scan_store.update_progress(scan_id, 90, "Input Validation Scanner", "in-progress")
			time.sleep(1)
			if time.monotonic() > deadline:
				self._mark_timeout(
					scan_id,
					"Input Validation Scanner",
					sqli_findings,
					xss_findings,
					header_findings,
					input_findings,
				)
				return

			current_record = self.scan_store.get_scan(scan_id) or {}
			scan_meta = {
				"scan_id": current_record.get("scan_id", scan_id),
				"url": current_record.get("url", url),
				"scan_type": current_record.get("scan_type", scan_type),
				"started_at": current_record.get("started_at", datetime.utcnow().isoformat()),
			}
			if len(current_modules) > 5:
				current_modules[5]["status"] = "running"
				current_modules[5]["details"] = "Building report"
				self.scan_store.update_scan_progress(scan_id, modules=current_modules, stats=current_stats)
			self.scan_store.update_progress(scan_id, 100, "Report Generator", "in-progress")
			succeeded, full_result = self._execute_with_deadline(
				lambda: self.report_generator.generate(
					scan_meta,
					sqli_findings,
					xss_findings,
					header_findings,
					input_findings,
				),
				deadline,
				"Report Generator",
			)
			if not succeeded:
				self._mark_timeout(
					scan_id,
					"Report Generator",
					sqli_findings,
					xss_findings,
					header_findings,
					input_findings,
				)
				return
			if len(current_modules) > 5:
				current_modules[5]["status"] = "completed"
				current_modules[5]["details"] = "Report ready"
				self.scan_store.update_scan_progress(scan_id, modules=current_modules, stats=current_stats)

			merged_record = dict(current_record)
			merged_record.update(full_result)
			merged_record["status"] = "completed"
			merged_record["progress"] = 100
			merged_record["current_module"] = "Completed"
			merged_record["completed_at"] = datetime.utcnow().isoformat()
			self.scan_store.save_scan(scan_id, merged_record)
		except Exception as exc:
			logging.exception("Scan %s failed: %s", scan_id, exc)
			record = self.scan_store.get_scan(scan_id) or {
				"scan_id": scan_id,
				"url": url,
				"scan_type": scan_type,
				"started_at": datetime.utcnow().isoformat(),
			}
			existing_progress = record.get("progress")
			record["status"] = "failed"
			record["current_module"] = "Failed"
			record["completed_at"] = datetime.utcnow().isoformat()
			record["progress"] = existing_progress if isinstance(existing_progress, (int, float)) else 0
			record["results"] = {
				"sql_injection": sqli_findings,
				"xss": xss_findings,
				"headers": header_findings,
				"input_validation": input_findings,
			}
			self.scan_store.save_scan(scan_id, record)

	def _execute_with_deadline(self, fn, deadline: float, module_name: str):
		remaining = deadline - time.monotonic()
		if remaining <= 0:
			return False, None

		result_holder = {}
		error_holder = {}

		def _runner():
			try:
				result_holder["value"] = fn()
			except Exception as exc:
				error_holder["error"] = exc

		worker = threading.Thread(target=_runner, daemon=True)
		worker.start()
		worker.join(remaining)

		if worker.is_alive():
			logging.warning("Module %s exceeded remaining scan time budget", module_name)
			return False, None

		if "error" in error_holder:
			raise error_holder["error"]

		return True, result_holder.get("value")

	def _mark_timeout(
		self,
		scan_id: str,
		module_name: str,
		sqli_findings: list,
		xss_findings: list,
		header_findings: list,
		input_findings: list,
	) -> None:
		record = self.scan_store.get_scan(scan_id) or {"scan_id": scan_id}
		record["status"] = "timeout"
		record["current_module"] = module_name
		record["completed_at"] = datetime.utcnow().isoformat()
		record["results"] = {
			"sql_injection": sqli_findings,
			"xss": xss_findings,
			"headers": header_findings,
			"input_validation": input_findings,
		}
		self.scan_store.save_scan(scan_id, record)
