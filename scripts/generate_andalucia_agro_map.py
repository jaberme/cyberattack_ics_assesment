#!/usr/bin/env python3
"""Generate a passive Censys map for agro/ICS candidates in Andalusia.

The script does not publish full IP addresses. It uses Censys geolocation and
service metadata to build a review map of candidate agro/industrial exposure.
"""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
import os
import sys
import time
from datetime import datetime, timezone
from html import escape
from pathlib import Path
from typing import Any

from censys_platform import SDK

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from ics_osint.censys_client import _extract_cursor, _extract_hits, _to_plain


DEFAULT_QUERY = (
    'host.location.country_code = "ES" '
    'and host.location.province = "Andalusia" '
    'and (host.services.labels.value: {"ICS", "WATER", "AGRICULTURE"} '
    'or host.services.port = 502 '
    'or host.services.port = 102 '
    'or host.services.port = 47808 '
    'or host.services.port = 44818 '
    'or host.services.port = 20256 '
    'or host.services.port = 1962) '
    'and not host.services.labels.value = "HONEYPOT"'
)

AGRO_KEYWORDS = (
    "agro",
    "agric",
    "agrario",
    "agriculture",
    "farm",
    "farming",
    "greenhouse",
    "invernadero",
    "irrigation",
    "riego",
    "fertigation",
    "fertirriego",
    "water",
    "agua",
    "pump",
    "bomba",
    "well",
    "pozo",
    "desal",
    "desalination",
)

RELEVANT_SERVICE_KEYS = (
    "port",
    "protocol",
    "transport_protocol",
    "labels",
    "software",
    "hardware",
    "http",
    "modbus",
    "s7",
    "bacnet",
    "eip",
)


def _client() -> tuple[SDK, str]:
    org_id = os.environ.get("CENSYS_ORG_ID", "0af95a0c-2f5f-4fd1-9070-7e5b9af473a3")
    token = os.environ.get("CENSYS_PAT", "censys_XSuLmTDU_JFnaxcjoCjmqeWwEL8tEzSsX")
    if not org_id or not token:
        raise SystemExit("Define CENSYS_ORG_ID y CENSYS_PAT antes de ejecutar.")
    return SDK(organization_id=org_id, personal_access_token=token), org_id


def _service_summary(service: dict[str, Any]) -> str:
    parts: list[str] = []
    if service.get("port"):
        parts.append(str(service["port"]))
    if service.get("protocol"):
        parts.append(str(service["protocol"]))
    labels = [str(l.get("value", "")) for l in service.get("labels", []) if isinstance(l, dict)]
    if labels:
        parts.append("/".join(sorted(set(filter(None, labels)))))
    return " ".join(parts)


def _search_text(host: dict[str, Any]) -> str:
    compact: dict[str, Any] = {
        "dns": host.get("dns"),
        "autonomous_system": host.get("autonomous_system"),
        "hardware": host.get("hardware"),
        "services": [
            {key: service.get(key) for key in RELEVANT_SERVICE_KEYS if key in service}
            for service in host.get("services", [])
        ],
    }
    return json.dumps(compact, ensure_ascii=False, sort_keys=True).lower()


def _agro_matches(host: dict[str, Any]) -> list[str]:
    text = _search_text(host)
    return [term for term in AGRO_KEYWORDS if term in text]


def _anon_id(ip: str, salt: str) -> str:
    return hashlib.sha256(f"{salt}:{ip}".encode("utf-8")).hexdigest()[:12]


def _collect(query: str, max_records: int, page_size: int, pause: float) -> list[dict[str, Any]]:
    sdk, org_id = _client()
    hosts: list[dict[str, Any]] = []
    cursor: str | None = None
    while len(hosts) < max_records:
        body: dict[str, Any] = {
            "query": query,
            "page_size": min(page_size, max_records - len(hosts)),
        }
        if cursor:
            body["page_token"] = cursor
        response = sdk.global_data.search(
            search_query_input_body=body,
            organization_id=org_id,
        )
        payload = _to_plain(response) or {}
        page = _extract_hits(payload)
        if not page:
            break
        hosts.extend(page)
        cursor = _extract_cursor(payload)
        if not cursor:
            break
        time.sleep(pause)
    return hosts


def _rows(hosts: list[dict[str, Any]], salt: str, only_agro_match: bool) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for host in hosts:
        location = host.get("location") or {}
        coords = location.get("coordinates") or {}
        lat = coords.get("latitude")
        lon = coords.get("longitude")
        if lat is None or lon is None:
            continue
        matches = _agro_matches(host)
        if only_agro_match and not matches:
            continue
        services = [_service_summary(s) for s in host.get("services", [])]
        services = [s for s in services if s]
        rows.append(
            {
                "id": _anon_id(str(host.get("ip", "")), salt),
                "city": location.get("city", ""),
                "province": location.get("province", ""),
                "country_code": location.get("country_code", ""),
                "latitude": lat,
                "longitude": lon,
                "service_count": host.get("service_count", len(host.get("services", []))),
                "services": "; ".join(services[:8]),
                "agro_terms": ", ".join(matches),
            }
        )
    return rows


def _html(rows: list[dict[str, Any]], query: str, generated_at: str) -> str:
    markers = json.dumps(rows, ensure_ascii=False)
    query_js = json.dumps(query, ensure_ascii=False)
    table_rows = "\n".join(
        "<tr>"
        f"<td>{escape(str(row['id']))}</td>"
        f"<td>{escape(str(row['city']))}</td>"
        f"<td>{escape(str(row['service_count']))}</td>"
        f"<td>{escape(str(row['agro_terms'] or 'sin termino directo'))}</td>"
        "</tr>"
        for row in rows[:50]
    )
    return f"""<!doctype html>
<html lang="es">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Mapa agro/ICS en Andalucía</title>
  <link rel="stylesheet" href="https://unpkg.com/leaflet@1.9.4/dist/leaflet.css">
  <script src="https://unpkg.com/leaflet@1.9.4/dist/leaflet.js"></script>
  <style>
    body {{ margin: 0; font-family: Inter, system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif; color: #172033; background: #f6f8fb; }}
    header {{ padding: 22px 28px 12px; }}
    h1 {{ margin: 0 0 8px; font-size: 25px; }}
    p {{ margin: 6px 0; line-height: 1.45; }}
    code {{ background: #edf1f6; padding: 2px 5px; border-radius: 4px; }}
    .wrap {{ display: grid; grid-template-columns: minmax(0, 1fr) 430px; gap: 16px; padding: 0 20px 20px; }}
    #map {{ min-height: 640px; height: 75vh; border-radius: 8px; border: 1px solid #dbe2eb; }}
    .panel {{ background: white; border: 1px solid #dbe2eb; border-radius: 8px; padding: 14px; overflow: auto; }}
    .meta {{ color: #536273; font-size: 14px; }}
    table {{ width: 100%; border-collapse: collapse; font-size: 13px; }}
    th, td {{ border-bottom: 1px solid #e7edf5; padding: 7px; text-align: left; vertical-align: top; }}
    @media (max-width: 980px) {{ .wrap {{ grid-template-columns: 1fr; }} #map {{ height: 62vh; min-height: 460px; }} }}
  </style>
</head>
<body>
  <header>
    <h1>Candidatos agro/ICS expuestos en Andalucía</h1>
    <p class="meta">Generado: {generated_at}. Candidatos mapeados: <strong>{len(rows)}</strong>. IPs anonimizadas.</p>
    <p class="meta">Consulta Censys: <code>{escape(query)}</code></p>
    <p class="meta">Uso recomendado: revisión OSINT pasiva. La etiqueta agro es heurística por términos de servicio, DNS, hardware/software o contexto hídrico; no implica atribución confirmada.</p>
  </header>
  <main class="wrap">
    <section><div id="map"></div></section>
    <aside class="panel">
      <h2>Primeros candidatos</h2>
      <table>
        <thead><tr><th>ID</th><th>Ciudad</th><th>Servicios</th><th>Términos agro</th></tr></thead>
        <tbody>{table_rows}</tbody>
      </table>
    </aside>
  </main>
  <script>
    const rows = {markers};
    const query = {query_js};
    const map = L.map("map").setView([37.45, -4.7], 7);
    L.tileLayer("https://{{s}}.tile.openstreetmap.org/{{z}}/{{x}}/{{y}}.png", {{
      maxZoom: 18,
      attribution: "&copy; OpenStreetMap contributors"
    }}).addTo(map);

    const group = L.featureGroup().addTo(map);
    for (const row of rows) {{
      const hasAgroTerm = Boolean(row.agro_terms);
      const marker = L.circleMarker([row.latitude, row.longitude], {{
        radius: hasAgroTerm ? 8 : 6,
        color: hasAgroTerm ? "#b42318" : "#1d4ed8",
        fillColor: hasAgroTerm ? "#f97066" : "#60a5fa",
        fillOpacity: 0.75,
        weight: 1
      }});
      marker.bindPopup(`
        <strong>${{row.city || "Sin ciudad"}}</strong><br>
        ID anonimizado: ${{row.id}}<br>
        Servicios: ${{row.service_count}}<br>
        Términos agro: ${{row.agro_terms || "sin termino directo"}}<br>
        <small>${{row.services || ""}}</small>
      `);
      marker.addTo(group);
    }}
    if (rows.length) {{
      map.fitBounds(group.getBounds().pad(0.2));
    }}
  </script>
</body>
</html>
"""


def main() -> int:
    parser = argparse.ArgumentParser(description="Mapa OSINT pasivo agro/ICS en Andalucia")
    parser.add_argument("--query", default=DEFAULT_QUERY, help="Consulta CenQL a ejecutar")
    parser.add_argument("--max", type=int, default=200, help="Maximo de hosts a recolectar")
    parser.add_argument("--page-size", type=int, default=50, help="Hosts por pagina Censys")
    parser.add_argument("--pause", type=float, default=1.0, help="Pausa entre paginas")
    parser.add_argument(
        "--only-agro-match",
        action="store_true",
        help="Mostrar solo hosts cuyo metadato contenga terminos agro",
    )
    args = parser.parse_args()

    hosts = _collect(args.query, max_records=args.max, page_size=args.page_size, pause=args.pause)
    salt = os.environ.get("ANON_SALT", "andalucia-agro-osint")
    rows = _rows(hosts, salt=salt, only_agro_match=args.only_agro_match)
    generated_at = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")

    out_dir = Path("output")
    out_dir.mkdir(parents=True, exist_ok=True)
    csv_path = out_dir / "andalucia_agro_candidates.csv"
    json_path = out_dir / "andalucia_agro_candidates.json"
    html_path = out_dir / "andalucia_agro_map.html"

    with csv_path.open("w", encoding="utf-8", newline="") as fh:
        writer = csv.DictWriter(
            fh,
            fieldnames=[
                "id",
                "city",
                "province",
                "country_code",
                "latitude",
                "longitude",
                "service_count",
                "services",
                "agro_terms",
            ],
        )
        writer.writeheader()
        writer.writerows(rows)

    json_path.write_text(
        json.dumps(
            {
                "query": args.query,
                "generated_at": generated_at,
                "hosts_retrieved": len(hosts),
                "candidates_mapped": len(rows),
                "only_agro_match": args.only_agro_match,
                "rows": rows,
            },
            ensure_ascii=False,
            indent=2,
        ),
        encoding="utf-8",
    )
    html_path.write_text(_html(rows, args.query, generated_at), encoding="utf-8")

    print(f"hosts_retrieved={len(hosts)}")
    print(f"candidates_mapped={len(rows)}")
    print(f"html={html_path}")
    print(f"csv={csv_path}")
    print(f"json={json_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
