"""Fase 5b — Correlación de fingerprints con vulnerabilidades.

Combina tres fuentes, siguiendo la metodología de la Sección 4.4 del TFG:

  1. Catálogo semilla offline (`data/cve_seed.yaml`): CVEs ICS de alto impacto
     ya conocidas (Tabla 2.4). Permite correlación rápida y funcionamiento sin
     red para los fabricantes clave (Unitronics, Rockwell, Siemens, Schneider,
     ABB...).
  2. NVD API 2.0 (opcional): correlación dinámica por CPE o palabra clave.
  3. Catálogo KEV de CISA (opcional): marca las CVEs explotadas «in the wild»,
     lo que eleva la severidad del hallazgo.

IMPORTANTE — la correlación es *potencial*: se basa en el fingerprint indexado,
no en un escaneo activo. Confirmar la explotabilidad real requeriría una prueba
activa que la metodología descarta por principio ético.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import requests
import yaml

from .fingerprint import Fingerprint, extract_fingerprints, host_ip, host_country, host_ports
from .nvd_client import NvdClient
from .severity import (
    SeverityInputs,
    classify,
    max_level,
    REMOTE_ACCESS_PORTS,
    INSECURE_PROTOCOL_PORTS,
)


# --------------------------------------------------------------------------- #
# Catálogos
# --------------------------------------------------------------------------- #
def load_seed_catalog(path: str | Path) -> list[dict]:
    """Carga el catálogo semilla de CVEs ICS conocidas."""
    p = Path(path)
    if not p.exists():
        return []
    with p.open("r", encoding="utf-8") as fh:
        data = yaml.safe_load(fh) or {}
    return data.get("cves", [])


def load_kev_catalog(url: str, cache: str | Path | None = None) -> set[str]:
    """Descarga (o lee de caché) el catálogo KEV de CISA y devuelve el set de CVE-IDs.

    Tolera el modo offline: si no hay red ni caché, devuelve un set vacío.
    """
    cache_path = Path(cache) if cache else None
    if cache_path and cache_path.exists():
        try:
            with cache_path.open("r", encoding="utf-8") as fh:
                data = json.load(fh)
            return {v["cveID"] for v in data.get("vulnerabilities", [])}
        except Exception:
            pass
    try:
        resp = requests.get(url, timeout=30)
        if resp.status_code == 200:
            data = resp.json()
            if cache_path:
                cache_path.parent.mkdir(parents=True, exist_ok=True)
                with cache_path.open("w", encoding="utf-8") as fh:
                    json.dump(data, fh)
            return {v["cveID"] for v in data.get("vulnerabilities", [])}
    except requests.RequestException:
        pass
    return set()


# --------------------------------------------------------------------------- #
# Correlación
# --------------------------------------------------------------------------- #
def _matches_seed(fp: Fingerprint, seed_entry: dict) -> bool:
    """True si el fingerprint encaja con una entrada del catálogo semilla."""
    hay = " ".join(
        str(x).lower() for x in (fp.vendor, fp.product, fp.version, fp.protocol) if x
    )
    keywords = [k.lower() for k in seed_entry.get("match_keywords", [])]
    if not keywords:
        return False
    # Todas las palabras clave de la entrada deben aparecer (AND).
    return all(k in hay for k in keywords)


def _seed_to_cve(entry: dict, kev: set[str]) -> dict:
    cve_id = entry.get("cve", "")
    return {
        "id": cve_id,
        "cvss": entry.get("cvss"),
        "severity": entry.get("severity"),
        "vector": entry.get("vector"),
        "description": entry.get("notes", ""),
        "source": "seed",
        "in_kev": cve_id in kev or bool(entry.get("kev")),
        "default_credentials": bool(entry.get("default_credentials")),
    }


def correlate_fingerprint(
    fp: Fingerprint,
    seed: list[dict],
    kev: set[str],
    nvd: NvdClient | None,
    use_keyword_search: bool = False,
) -> list[dict]:
    """Devuelve la lista de CVEs potencialmente aplicables a un fingerprint."""
    cves: dict[str, dict] = {}

    # 1) Catálogo semilla (offline, rápido).
    for entry in seed:
        if _matches_seed(fp, entry):
            cve = _seed_to_cve(entry, kev)
            cves[cve["id"]] = cve

    # 2) NVD por CPE (preferente) o palabra clave.
    if nvd is not None:
        nvd_hits: list[dict] = []
        if fp.cpe:
            nvd_hits = nvd.search_by_cpe(fp.cpe)
        elif use_keyword_search and (kw := fp.keyword()):
            nvd_hits = nvd.search_by_keyword(kw)
        for hit in nvd_hits:
            cid = hit.get("id")
            if not cid:
                continue
            hit = dict(hit)
            hit["source"] = "nvd"
            hit["in_kev"] = cid in kev
            hit.setdefault("default_credentials", False)
            # No sobreescribir un match de la semilla (más específico/curado).
            cves.setdefault(cid, hit)

    return list(cves.values())


def analyze_host(
    host: dict,
    seed: list[dict],
    kev: set[str],
    nvd: NvdClient | None = None,
    use_keyword_search: bool = False,
) -> dict:
    """Analiza un host completo: fingerprints, CVEs y severidad agregada.

    Devuelve un registro con la severidad máxima del host y el detalle por CVE.
    """
    fingerprints = extract_fingerprints(host)
    ports = host_ports(host)

    all_cves: dict[str, dict] = {}
    for fp in fingerprints:
        for cve in correlate_fingerprint(fp, seed, kev, nvd, use_keyword_search):
            all_cves.setdefault(cve["id"], cve)

    cve_list = list(all_cves.values())
    max_cvss = max((c["cvss"] for c in cve_list if c.get("cvss")), default=None)
    in_kev = any(c.get("in_kev") for c in cve_list)
    default_creds = any(c.get("default_credentials") for c in cve_list)

    exposed_remote = bool(ports & REMOTE_ACCESS_PORTS)
    insecure_only = bool(ports & INSECURE_PROTOCOL_PORTS) and not cve_list
    info_disclosure = any(fp.product or fp.version for fp in fingerprints)

    level = classify(
        SeverityInputs(
            max_cvss=max_cvss,
            in_kev=in_kev,
            exposed_remote_access=exposed_remote,
            default_credentials=default_creds,
            insecure_protocol_only=insecure_only,
            info_disclosure=info_disclosure,
        )
    )

    return {
        "ip": host_ip(host),
        "country_code": host_country(host),
        "ports": sorted(p for p in ports if isinstance(p, int)),
        "fingerprints": [fp.to_dict() for fp in fingerprints],
        "cves": cve_list,
        "max_cvss": max_cvss,
        "in_kev": in_kev,
        "severity": level,
    }
