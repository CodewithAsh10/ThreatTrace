import json
import logging
import time
import urllib.parse
import uuid
from io import BytesIO

from flask import Flask, Response, jsonify, render_template, request, send_file

from config import FLASK_DEBUG, FLASK_HOST, FLASK_PORT
from reports import PDFGenerator
from scanner.scan_controller import ScanController
from storage import ScanStore


logging.basicConfig(level=logging.INFO)

app = Flask(__name__)
scan_store = ScanStore()
scan_controller = ScanController(scan_store)


def _is_valid_url(url: str) -> bool:
	try:
		parsed = urllib.parse.urlparse(url)
	except Exception:
		return False
	return parsed.scheme in {"http", "https"} and bool(parsed.netloc)


@app.post("/api/scan")
def create_scan():
	payload = request.get_json(silent=True) or {}
	url = payload.get("url", "")
	scan_type = payload.get("scan_type", "full")

	if not _is_valid_url(url):
		return jsonify({"error": "Invalid URL"}), 400

	scan_id = str(uuid.uuid4())
	scan_controller.start_scan(scan_id, url, scan_type)
	return jsonify({"scan_id": scan_id, "status": "started"}), 201


@app.get("/api/scan/<scan_id>/status")
def scan_status(scan_id):
	record = scan_store.get_scan(scan_id)
	if not record:
		return jsonify({"error": "Scan not found"}), 404

	return jsonify(
		{
			"scan_id": record.get("scan_id"),
			"url": record.get("url"),
			"status": record.get("status"),
			"progress": record.get("progress"),
			"current_module": record.get("current_module"),
		}
	)


@app.get("/api/scan/<scan_id>/results")
def scan_results(scan_id):
	record = scan_store.get_scan(scan_id)
	if not record:
		return jsonify({"error": "Scan not found"}), 404
	return jsonify(record)


@app.get("/api/scan/<scan_id>/report/pdf")
def scan_report_pdf(scan_id):
	record = scan_store.get_scan(scan_id)
	if not record:
		return jsonify({"error": "Scan not found"}), 404

	pdf_bytes = PDFGenerator().generate_pdf(record)
	return send_file(
		BytesIO(pdf_bytes),
		mimetype="application/pdf",
		as_attachment=True,
		download_name=f"vulnguard_report_{scan_id[:8]}.pdf",
	)


@app.get("/api/scan/<scan_id>/report/json")
def scan_report_json(scan_id):
	record = scan_store.get_scan(scan_id)
	if not record:
		return jsonify({"error": "Scan not found"}), 404

	payload = json.dumps(record, default=str).encode("utf-8")
	return send_file(
		BytesIO(payload),
		mimetype="application/json",
		as_attachment=True,
		download_name=f"vulnguard_report_{scan_id[:8]}.json",
	)


@app.get("/api/scans/history")
def scan_history():
	records = scan_store.get_all_scans()
	history = []
	for record in records:
		summary = record.get("summary") or {
			"HIGH": 0,
			"MEDIUM": 0,
			"LOW": 0,
			"INFO": 0,
			"total": 0,
		}
		history.append(
			{
				"scan_id": record.get("scan_id"),
				"url": record.get("url"),
				"scan_type": record.get("scan_type"),
				"status": record.get("status"),
				"started_at": record.get("started_at"),
				"completed_at": record.get("completed_at"),
				"progress": record.get("progress"),
				"score": record.get("score"),
				"summary": {
					"HIGH": summary.get("HIGH", 0),
					"MEDIUM": summary.get("MEDIUM", 0),
					"LOW": summary.get("LOW", 0),
					"INFO": summary.get("INFO", 0),
					"total": summary.get("total", 0),
				},
			}
		)

	history.sort(key=lambda item: item.get("started_at") or "", reverse=True)
	return jsonify(history)


@app.delete("/api/scan/<scan_id>")
def delete_scan(scan_id):
	record = scan_store.get_scan(scan_id)
	if not record:
		return jsonify({"error": "Scan not found"}), 404

	scan_store.delete_scan(scan_id)
	return jsonify({"message": "Scan deleted"})


@app.get("/api/scan/<scan_id>/stream")
def scan_stream(scan_id):
	initial = scan_store.get_scan(scan_id)
	if not initial:
		return jsonify({"error": "Scan not found"}), 404

	def event_stream():
		emitted_log_count = 0
		emitted_finding_count = 0
		while True:
			record = scan_store.get_scan(scan_id)
			if not record:
				payload = {
					"scan_id": scan_id,
					"status": "not_found",
					"progress": 0,
					"current_module": "Deleted",
				}
				yield f"event: complete\ndata: {json.dumps(payload)}\n\n"
				return

			status = record.get("status")

			progress_log = record.get("progress_log", [])
			for entry in progress_log[emitted_log_count:]:
				yield f"event: log\ndata: {json.dumps(entry)}\n\n"
			emitted_log_count = len(progress_log)

			pending_findings = record.get("pending_findings", [])
			for finding in pending_findings[emitted_finding_count:]:
				yield f"event: finding\ndata: {json.dumps(finding)}\n\n"
			emitted_finding_count = len(pending_findings)

			progress_payload = {
				"progress": record.get("progress", 0),
				"current_module": record.get("current_module", ""),
				"modules": record.get("modules", []),
				"stats": record.get("stats", {}),
				"log_entry": progress_log[-1] if progress_log else None,
			}
			yield f"event: progress\ndata: {json.dumps(progress_payload)}\n\n"

			if status in {"completed", "failed", "timeout"}:
				complete_payload = {
					"scan_id": scan_id,
					"score": record.get("score"),
					"status": status,
					"redirect": f"/scan/{scan_id}/results",
				}
				yield f"event: complete\ndata: {json.dumps(complete_payload)}\n\n"
				return

			time.sleep(1)

	return Response(
		event_stream(),
		mimetype="text/event-stream",
		headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
	)


@app.get("/")
def index_page():
	return render_template("index.html")


@app.get("/scan/<scan_id>/progress")
def progress_page(scan_id):
	return render_template("scan_progress.html", scan_id=scan_id)


@app.get("/scan/<scan_id>/results")
def results_page(scan_id):
	return render_template("results.html", scan_id=scan_id)


@app.get("/history")
def history_page():
	return render_template("history.html")


if __name__ == "__main__":
	app.run(host=FLASK_HOST, port=FLASK_PORT, debug=FLASK_DEBUG)
