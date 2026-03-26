import os


RESULTS_DIR = "results"
REQUEST_TIMEOUT = 10
RATE_LIMIT_DELAY = 0.5
MAX_SCAN_TIME = 120
FLASK_HOST = "127.0.0.1"
FLASK_PORT = 5000
FLASK_DEBUG = True
SCORE_DEDUCTIONS = {"HIGH": 25, "MEDIUM": 15, "LOW": 5, "INFO": 1}
SEVERITY_LEVELS = ["HIGH", "MEDIUM", "LOW", "INFO"]
PAYLOADS_DIR = os.path.join(os.path.dirname(__file__), "scanner", "payloads")
