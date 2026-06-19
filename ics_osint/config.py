"""Carga y validación de configuración y del catálogo de consultas.

Los secretos (tokens, claves de API) NUNCA se almacenan en el repositorio.
En `config.yaml` se referencian mediante la sintaxis ``${env:NOMBRE_VARIABLE}``
y se resuelven desde el entorno en tiempo de ejecución.
"""

from __future__ import annotations

import os
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

_ENV_RE = re.compile(r"^\$\{env:([A-Za-z_][A-Za-z0-9_]*)\}$")


def _resolve_env(value: Any) -> Any:
    """Sustituye recursivamente los marcadores ``${env:VAR}`` por su valor real."""
    if isinstance(value, str):
        m = _ENV_RE.match(value.strip())
        if m:
            return os.environ.get(m.group(1), "")
        return value
    if isinstance(value, dict):
        return {k: _resolve_env(v) for k, v in value.items()}
    if isinstance(value, list):
        return [_resolve_env(v) for v in value]
    return value


def load_yaml(path: str | Path) -> dict:
    """Lee un YAML y resuelve los marcadores de entorno."""
    path = Path(path)
    if not path.exists():
        raise FileNotFoundError(f"No se encuentra el archivo: {path}")
    with path.open("r", encoding="utf-8") as fh:
        data = yaml.safe_load(fh) or {}
    return _resolve_env(data)


@dataclass
class Paths:
    """Rutas de trabajo del pipeline (se crean si no existen)."""

    base: Path = Path("data")
    raw_dir: Path = Path("data/raw")
    clean_dir: Path = Path("data/clean")
    cve_dir: Path = Path("data/cve")
    output_dir: Path = Path("output")

    def ensure(self) -> None:
        for p in (self.base, self.raw_dir, self.clean_dir, self.cve_dir, self.output_dir):
            p.mkdir(parents=True, exist_ok=True)


@dataclass
class Config:
    """Configuración consolidada del toolkit."""

    raw: dict = field(default_factory=dict)
    paths: Paths = field(default_factory=Paths)

    # --- Censys Platform ---
    @property
    def censys_org_id(self) -> str:
        return self.raw.get("censys", {}).get("organization_id", "")

    @property
    def censys_token(self) -> str:
        return self.raw.get("censys", {}).get("personal_access_token", "")

    @property
    def censys_page_size(self) -> int:
        return int(self.raw.get("censys", {}).get("page_size", 100))

    @property
    def default_max_records(self) -> int:
        return int(self.raw.get("collection", {}).get("default_max_records", 200))

    # --- NVD ---
    @property
    def nvd_api_key(self) -> str:
        return self.raw.get("nvd", {}).get("api_key", "")

    @property
    def kev_url(self) -> str:
        return self.raw.get("nvd", {}).get(
            "kev_url",
            "https://www.cisa.gov/sites/default/files/feeds/"
            "known_exploited_vulnerabilities.json",
        )

    # --- Filtros ---
    @property
    def cloud_asn_names(self) -> list[str]:
        return self.raw.get("filters", {}).get(
            "cloud_asn_names",
            ["Amazon", "Google", "Microsoft", "DigitalOcean", "OVH", "Hetzner"],
        )

    @property
    def honeypot_labels(self) -> list[str]:
        return [s.lower() for s in self.raw.get("filters", {}).get(
            "honeypot_labels", ["honeypot", "HONEYPOT"]
        )]

    # --- Regiones (código de país -> región del estudio) ---
    @property
    def regions(self) -> dict[str, str]:
        return self.raw.get("regions", {})

    # --- Anonimización ---
    @property
    def anonymization(self) -> dict:
        return self.raw.get("anonymization", {"method": "truncate", "keep_octets": 2})


def load_config(path: str | Path) -> Config:
    """Construye un objeto `Config` a partir de un `config.yaml`."""
    raw = load_yaml(path)
    p = raw.get("paths", {})
    paths = Paths(
        base=Path(p.get("base", "data")),
        raw_dir=Path(p.get("raw_dir", "data/raw")),
        clean_dir=Path(p.get("clean_dir", "data/clean")),
        cve_dir=Path(p.get("cve_dir", "data/cve")),
        output_dir=Path(p.get("output_dir", "output")),
    )
    return Config(raw=raw, paths=paths)


def load_queries(path: str | Path) -> list[dict]:
    """Aplana el catálogo de consultas YAML en una lista de dicts.

    Cada elemento tiene: ``id``, ``region``, ``description`` y ``cenql``.
    """
    data = load_yaml(path)
    queries: list[dict] = []
    for region, items in (data.get("queries", {}) or {}).items():
        for item in items or []:
            queries.append(
                {
                    "id": item["id"],
                    "region": region,
                    "description": item.get("description", ""),
                    "cenql": item["cenql"].strip(),
                }
            )
    return queries
