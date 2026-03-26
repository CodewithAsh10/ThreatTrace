import json
import logging
import os
import threading
from datetime import datetime

try:
	from ..config import RESULTS_DIR
except ImportError:
	from config import RESULTS_DIR


class ScanStore:
	def __init__(self, results_dir=RESULTS_DIR):
		self.scans = {}
		self._lock = threading.RLock()
		self.results_dir = results_dir
		os.makedirs(results_dir, exist_ok=True)
		self._load_existing()

	def _load_existing(self):
		for filename in os.listdir(self.results_dir):
			if not filename.endswith(".json"):
				continue

			file_path = os.path.join(self.results_dir, filename)
			try:
				with open(file_path, "r", encoding="utf-8") as file:
					data = json.load(file)

				scan_id = data.get("scan_id")
				if not scan_id:
					scan_id = self._derive_scan_id_from_filename(filename)

				if not scan_id:
					logging.warning(
						"%s Malformed scan file %s missing scan_id; quarantining",
						datetime.utcnow().isoformat(),
						file_path,
					)
					self._quarantine_malformed_file(file_path, filename)
					continue

				if data.get("scan_id") != scan_id:
					data = dict(data)
					data["scan_id"] = scan_id

				with self._lock:
					self.scans[scan_id] = data
			except Exception as exc:
				logging.warning(
					"%s Failed to load scan file %s: %s",
					datetime.utcnow().isoformat(),
					file_path,
					exc,
				)

	def save_scan(self, scan_id, scan_data):
		normalized_scan = dict(scan_data or {})
		normalized_scan["scan_id"] = scan_id
		normalized_scan.setdefault("progress_log", [])
		normalized_scan.setdefault("modules", [])
		normalized_scan.setdefault("stats", {})
		normalized_scan.setdefault("pending_findings", [])
		file_path = os.path.join(self.results_dir, f"scan_{scan_id}.json")

		with self._lock:
			self.scans[scan_id] = normalized_scan
			scan_snapshot = dict(normalized_scan)

		try:
			with open(file_path, "w", encoding="utf-8") as file:
				json.dump(scan_snapshot, file, indent=2, default=str)
		except Exception as exc:
			logging.error("Failed to save scan %s to %s: %s", scan_id, file_path, exc)

	def get_scan(self, scan_id):
		with self._lock:
			scan = self.scans.get(scan_id)
			if isinstance(scan, dict):
				return dict(scan)
			return scan

	def get_all_scans(self):
		with self._lock:
			return [dict(scan) if isinstance(scan, dict) else scan for scan in self.scans.values()]

	def delete_scan(self, scan_id):
		with self._lock:
			self.scans.pop(scan_id, None)
		file_path = os.path.join(self.results_dir, f"scan_{scan_id}.json")

		try:
			if os.path.exists(file_path):
				os.remove(file_path)
		except Exception as exc:
			logging.error("Failed to delete scan file %s: %s", file_path, exc)

	def update_progress(self, scan_id, progress, current_module, status):
		with self._lock:
			if scan_id in self.scans:
				self.scans[scan_id]["progress"] = progress
				self.scans[scan_id]["current_module"] = current_module
				self.scans[scan_id]["status"] = status

	def update_scan_progress(self, scan_id, *, modules=None, stats=None, log_entry=None, finding=None):
		with self._lock:
			if scan_id not in self.scans:
				return

			record = self.scans[scan_id]
			record.setdefault("progress_log", [])
			record.setdefault("modules", [])
			record.setdefault("stats", {})
			record.setdefault("pending_findings", [])

			if log_entry is not None:
				record["progress_log"].append(log_entry)

			if modules is not None:
				record["modules"] = modules

			if stats is not None:
				record["stats"].update(stats)

			if finding is not None:
				record["pending_findings"].append(finding)

	def _derive_scan_id_from_filename(self, filename):
		base_name, extension = os.path.splitext(filename)
		if extension.lower() != ".json":
			return None
		if base_name.startswith("scan_") and len(base_name) > len("scan_"):
			return base_name[len("scan_") :]
		return None

	def _quarantine_malformed_file(self, file_path, filename):
		malformed_name = f"malformed_{filename}"
		malformed_path = os.path.join(self.results_dir, malformed_name)
		if file_path == malformed_path:
			return

		try:
			if not os.path.exists(malformed_path):
				os.replace(file_path, malformed_path)
			else:
				logging.warning("Malformed scan file already quarantined at %s", malformed_path)
		except Exception as exc:
			logging.warning("Failed to quarantine malformed scan file %s: %s", file_path, exc)
