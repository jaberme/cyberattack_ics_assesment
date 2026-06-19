"""Cliente para la NVD API 2.0 (National Vulnerability Database).

Automatiza la correlación manual con NVD descrita en la Sección 4.4 del TFG.
Respeta los límites de tasa públicos de NVD:
  - sin clave de API: 5 peticiones / 30 s  (intervalo ~6 s)
  - con clave de API: 50 peticiones / 30 s (intervalo ~0,6 s)

Endpoint: https://services.nvd.nist.gov/rest/json/cves/2.0
Solicita una clave gratuita en https://nvd.nist.gov/developers/request-an-api-key
"""

from __future__ import annotations

import time
from typing import Any

import requests

NVD_ENDPOINT = "https://services.nvd.nist.gov/rest/json/cves/2.0"


def _best_cvss(metrics: dict) -> tuple[float | None, str | None, str | None]:
    """Extrae (baseScore, severity, vectorString) priorizando CVSS v3.1 > v3.0 > v2."""
    for key in ("cvssMetricV31", "cvssMetricV30"):
        entries = metrics.get(key)
        if entries:
            data = entries[0].get("cvssData", {})
            return (
                data.get("baseScore"),
                data.get("baseSeverity"),
                data.get("vectorString"),
            )
    entries = metrics.get("cvssMetricV2")
    if entries:
        data = entries[0].get("cvssData", {})
        return (
            data.get("baseScore"),
            entries[0].get("baseSeverity"),
            data.get("vectorString"),
        )
    return (None, None, None)


def _parse_cve(item: dict) -> dict:
    cve = item.get("cve", {})
    descs = cve.get("descriptions", [])
    desc_en = next(
        (d.get("value") for d in descs if d.get("lang") == "en"),
        descs[0].get("value") if descs else "",
    )
    score, severity, vector = _best_cvss(cve.get("metrics", {}))
    return {
        "id": cve.get("id", ""),
        "cvss": score,
        "severity": severity,
        "vector": vector,
        "description": (desc_en or "")[:300],
    }


class NvdClient:
    """Cliente NVD con limitación de tasa y reintentos sobre 429/503."""

    def __init__(
        self,
        api_key: str = "",
        timeout: int = 30,
        max_retries: int = 3,
    ) -> None:
        self.api_key = api_key.strip()
        self.timeout = timeout
        self.max_retries = max_retries
        # Intervalo mínimo entre peticiones según el límite de tasa.
        self.min_interval = 0.7 if self.api_key else 6.5
        self._last_call = 0.0

    def _headers(self) -> dict:
        return {"apiKey": self.api_key} if self.api_key else {}

    def _throttle(self) -> None:
        elapsed = time.time() - self._last_call
        if elapsed < self.min_interval:
            time.sleep(self.min_interval - elapsed)
        self._last_call = time.time()

    def _request(self, params: dict) -> dict:
        for attempt in range(self.max_retries):
            self._throttle()
            try:
                resp = requests.get(
                    NVD_ENDPOINT,
                    params=params,
                    headers=self._headers(),
                    timeout=self.timeout,
                )
            except requests.RequestException:
                if attempt == self.max_retries - 1:
                    return {}
                time.sleep(2 * (attempt + 1))
                continue
            if resp.status_code == 200:
                return resp.json()
            if resp.status_code in (429, 503):
                time.sleep(6 * (attempt + 1))
                continue
            return {}
        return {}

    def search_by_cpe(self, cpe: str, results_per_page: int = 50) -> list[dict]:
        """Devuelve las CVEs asociadas a un CPE concreto."""
        data = self._request(
            {"cpeName": cpe, "resultsPerPage": results_per_page}
        )
        return [_parse_cve(v) for v in data.get("vulnerabilities", [])]

    def search_by_keyword(self, keyword: str, results_per_page: int = 20) -> list[dict]:
        """Búsqueda por palabras clave (fabricante/producto)."""
        if not keyword:
            return []
        data = self._request(
            {
                "keywordSearch": keyword,
                "keywordExactMatch": "",
                "resultsPerPage": results_per_page,
            }
        )
        return [_parse_cve(v) for v in data.get("vulnerabilities", [])]
