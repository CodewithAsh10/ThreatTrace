import logging
import time
import urllib.parse

import requests
import urllib3
from bs4 import BeautifulSoup
from urllib3.exceptions import InsecureRequestWarning

try:
	from ..config import RATE_LIMIT_DELAY, REQUEST_TIMEOUT
except ImportError:
	from config import RATE_LIMIT_DELAY, REQUEST_TIMEOUT


urllib3.disable_warnings(InsecureRequestWarning)


class Crawler:
	def crawl(self, url: str) -> dict:
		try:
			response = requests.get(url, timeout=REQUEST_TIMEOUT, verify=False)
			soup = BeautifulSoup(response.text, "lxml")
			forms = self._extract_forms(soup, url)
			params = self._extract_url_params(url)
			return {
				"url": url,
				"status_code": response.status_code,
				"headers": dict(response.headers),
				"html": response.text,
				"forms": forms,
				"params": params,
				"response": response,
				"error": None,
			}
		except requests.exceptions.RequestException as exc:
			logging.warning("Crawler request failed for %s: %s", url, exc)
			return {
				"url": url,
				"status_code": None,
				"headers": {},
				"html": "",
				"forms": [],
				"params": self._extract_url_params(url),
				"response": None,
				"error": str(exc),
			}
		finally:
			time.sleep(RATE_LIMIT_DELAY)

	def _extract_forms(self, soup: BeautifulSoup, base_url: str) -> list[dict]:
		forms = []
		for form in soup.find_all("form"):
			action = urllib.parse.urljoin(base_url, form.get("action", ""))
			method = form.get("method", "get").lower()
			fields = []
			for field in form.find_all(["input", "textarea", "select"]):
				field_type = field.get("type", "text")
				fields.append(
					{
						"name": field.get("name"),
						"type": field_type,
						"value": field.get("value", ""),
						"required": field.has_attr("required"),
						"maxlength": field.get("maxlength"),
						"pattern": field.get("pattern"),
					}
				)
			forms.append({"action": action, "method": method, "fields": fields})
		return forms

	def _extract_url_params(self, url: str) -> dict:
		parsed_url = urllib.parse.urlparse(url)
		query_params = urllib.parse.parse_qs(parsed_url.query)
		return {key: values[0] if values else "" for key, values in query_params.items()}
