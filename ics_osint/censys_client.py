"""Cliente PASIVO para la Censys Platform API.

Sustituye la consulta manual del Apéndice A del TFG por consultas programáticas
al índice de Censys. Importante: este cliente SOLO lee el índice de Censys
(equivalente a una búsqueda en cualquier motor público). No envía ningún
paquete a los sistemas indexados.

Dependencia: censys-platform >= 0.13  (``pip install censys-platform``)
Autenticación: Personal Access Token (Bearer) + organization_id.
Documentación: https://docs.censys.com/reference/get-started

Nota de compatibilidad
----------------------
La forma exacta de la respuesta del SDK (claves del payload, token de cursor)
puede variar entre versiones del paquete generado. La extracción está escrita
de forma defensiva (`_extract_hits`, `_extract_total`, `_extract_cursor`) y
admite varias formas conocidas. Si tu versión difiere, ajusta esos tres
helpers; el resto del pipeline trabaja sobre el JSON ya guardado y es
independiente del SDK.
"""

from __future__ import annotations

import json
import time
from pathlib import Path
from typing import Any, Iterable

# Proyección de campos OPCIONAL. ATENCIÓN: restringir `fields` a este conjunto
# hace que la Censys Platform devuelva los objetos `software` VACÍOS ([{}...]),
# lo que inutiliza el fingerprinting (vendor/product/cpe) y, con ello, la
# correlación con CVEs. Por eso el cliente, POR DEFECTO, NO envía `fields`
# (proyección completa del host). Esta lista se conserva solo como referencia.
DEFAULT_FIELDS = [
    "host.ip",
    "host.location.country",
    "host.location.country_code",
    "host.location.city",
    "host.location.province",
    "host.autonomous_system.name",
    "host.autonomous_system.asn",
    "host.labels",
    "host.services.port",
    "host.services.protocol",
    "host.services.service_name",
    "host.services.software",
    "host.services.labels.value",
]


def _to_plain(obj: Any) -> Any:
    """Convierte modelos pydantic / objetos del SDK en dict/list nativos."""
    if obj is None or isinstance(obj, (str, int, float, bool)):
        return obj
    if hasattr(obj, "model_dump"):
        try:
            return obj.model_dump()
        except Exception:
            pass
    if hasattr(obj, "dict"):
        try:
            return obj.dict()
        except Exception:
            pass
    if isinstance(obj, dict):
        return {k: _to_plain(v) for k, v in obj.items()}
    if isinstance(obj, (list, tuple)):
        return [_to_plain(v) for v in obj]
    return obj


def _unwrap_host(hit: dict) -> dict:
    """Extrae el registro de host plano de un 'hit' de la Censys Platform.

    En la Platform v3 cada resultado de búsqueda envuelve el host en
    ``host_v1.resource`` (modelo ``HostAssetWithMatchedServices`` -> ``Host``).
    Si el hit ya viene plano (p. ej. un fixture sintético), se devuelve tal cual.
    """
    if not isinstance(hit, dict):
        return hit
    host_v1 = hit.get("host_v1")
    if isinstance(host_v1, dict):
        resource = host_v1.get("resource")
        if isinstance(resource, dict):
            return resource
    return hit


def _extract_hits(payload: dict) -> list[dict]:
    """Localiza la lista de hosts en el payload, probando formas conocidas.

    Devuelve los hosts ya 'desenvueltos' (planos), de modo que el resto del
    pipeline (filters, fingerprint...) trabaje siempre sobre la misma forma.
    """
    candidates = (
        ("result", "result", "hits"),   # Censys Platform v3 (SDK >= 0.14)
        ("result", "hits"),
        ("result", "results"),
        ("data", "result", "hits"),
        ("hits",),
        ("results",),
    )
    for path in candidates:
        node: Any = payload
        ok = True
        for key in path:
            if isinstance(node, dict) and key in node:
                node = node[key]
            else:
                ok = False
                break
        if ok and isinstance(node, list):
            return [_unwrap_host(h) for h in node]
    return []


def _extract_total(payload: dict) -> int | None:
    """Localiza el contador total de resultados, si la API lo expone.

    En la Platform v3 el total llega como ``result.result.total_hits`` y es un
    número en coma flotante; se normaliza a entero.
    """
    for path in (
        ("result", "result", "total_hits"),   # Censys Platform v3
        ("result", "total"),
        ("result", "total_hits"),
        ("total",),
    ):
        node: Any = payload
        ok = True
        for key in path:
            if isinstance(node, dict) and key in node:
                node = node[key]
            else:
                ok = False
                break
        if ok and isinstance(node, (int, float)):
            return int(node)
    return None


def _extract_cursor(payload: dict) -> str | None:
    """Localiza el token de paginación (cursor 'next'), si existe."""
    for path in (
        ("result", "result", "next_page_token"),   # Censys Platform v3
        ("result", "links", "next"),
        ("result", "next"),
        ("links", "next"),
        ("next_page_token",),
        ("nextPageToken",),
    ):
        node: Any = payload
        ok = True
        for key in path:
            if isinstance(node, dict) and key in node:
                node = node[key]
            else:
                ok = False
                break
        if ok and node:
            return str(node)
    return None


class CensysPassiveClient:
    """Envoltorio mínimo y pasivo sobre el SDK de la Censys Platform."""

    def __init__(
        self,
        organization_id: str,
        personal_access_token: str,
        page_size: int = 100,
        pause_seconds: float = 1.0,
        fields: list[str] | None = None,
    ) -> None:
        if not organization_id or not personal_access_token:
            raise ValueError(
                "Faltan credenciales de Censys. Define organization_id y "
                "personal_access_token (vía variables de entorno y config.yaml)."
            )
        self.org_id = organization_id
        self.token = personal_access_token
        self.page_size = page_size
        self.pause = pause_seconds
        # None => proyección completa (necesaria para que `software` traiga
        # vendor/product/cpe). Restringir aquí vaciaría esos sub-campos.
        self.fields = fields
        self._sdk = None

    def _client(self):
        if self._sdk is None:
            try:
                from censys_platform import SDK  # import perezoso
            except ImportError as exc:  # pragma: no cover
                raise ImportError(
                    "Falta el paquete 'censys-platform'. Instálalo con:\n"
                    "    pip install censys-platform"
                ) from exc
            self._sdk = SDK(
                organization_id=self.org_id,
                personal_access_token=self.token,
            )
        return self._sdk

    def _search(self, query: str, cursor: str | None, page_size: int) -> dict:
        body: dict[str, Any] = {
            "query": query,
            "page_size": page_size,
        }
        if self.fields:
            # Solo si el usuario pide explícitamente una proyección reducida.
            body["fields"] = self.fields
        if cursor:
            # Censys Platform v3 pagina con 'page_token' (campo del input body).
            body["page_token"] = cursor
        sdk = self._client()
        res = sdk.global_data.search(
            search_query_input_body=body,
            organization_id=self.org_id or None,
        )
        return _to_plain(res) or {}

    def count(self, query: str) -> int | None:
        """Devuelve el contador total de hosts (barato: una sola página).

        Reproduce el «contador de resultados» que el TFG leía en la interfaz web.
        Puede devolver None si el plan/versión no expone el total.
        """
        payload = self._search(query, cursor=None, page_size=1)
        return _extract_total(payload)

    def collect(self, query: str, max_records: int = 200) -> dict:
        """Recolecta hasta `max_records` hosts paginando con cursor.

        Devuelve un dict con: ``query``, ``total`` (si disponible) y ``hosts``.
        """
        hosts: list[dict] = []
        cursor: str | None = None
        total: int | None = None
        while len(hosts) < max_records:
            remaining = max_records - len(hosts)
            page_size = min(self.page_size, remaining)
            payload = self._search(query, cursor=cursor, page_size=page_size)
            if total is None:
                total = _extract_total(payload)
            page = _extract_hits(payload)
            if not page:
                break
            hosts.extend(page)
            cursor = _extract_cursor(payload)
            if not cursor:
                break
            time.sleep(self.pause)
        return {"query": query, "total": total, "retrieved": len(hosts), "hosts": hosts}


def save_raw(result: dict, path: str | Path) -> None:
    """Persiste el resultado de una consulta como JSON reproducible."""
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as fh:
        json.dump(result, fh, ensure_ascii=False, indent=2)


def load_raw_dir(raw_dir: str | Path) -> Iterable[dict]:
    """Itera sobre todos los JSON crudos de un directorio."""
    for p in sorted(Path(raw_dir).glob("*.json")):
        with p.open("r", encoding="utf-8") as fh:
            yield json.load(fh)
