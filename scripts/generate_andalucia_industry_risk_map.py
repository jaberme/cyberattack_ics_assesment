#!/usr/bin/env python3
"""Generate an anonymized Censys exposure-risk map for Andalusia.

This script is intentionally passive: it only reads the Censys index. It does
not connect to, probe, scan, authenticate to, or screenshot any target device.

Outputs:
  - output/andalucia_industry_risk_map.html
  - output/andalucia_industry_risk_findings.csv
  - output/andalucia_industry_risk_findings.json
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
    'and not host.services.labels.value = "HONEYPOT" '
    "and ("
    'host.services.labels.value: {"ICS", "SCADA", "INDUSTRIAL_CONTROL", "ELECTRICAL", "WATER", "OIL_AND_GAS"} '
    "or host.services.port = 23 "
    "or host.services.port = 5900 "
    "or host.services.port = 5901 "
    "or host.services.port = 5902 "
    "or host.services.port = 5903 "
    "or host.services.port = 3389 "
    "or host.services.port = 502 "
    "or host.services.port = 102 "
    "or host.services.port = 47808 "
    "or host.services.port = 44818 "
    "or host.services.port = 20000 "
    "or host.services.port = 20256 "
    "or host.services.port = 1962 "
    "or host.services.port = 2455 "
    "or host.services.port = 11740"
    ")"
)

CLOUD_ASN_TERMS = (
    "amazon",
    "aws",
    "azure",
    "microsoft",
    "google cloud",
    "digitalocean",
    "ovh",
    "hetzner",
    "linode",
    "oracle cloud",
    "cloudflare",
)

RESIDENTIAL_ASN_TERMS = (
    "residential",
    "broadband",
    "adsl",
    "fibra",
    "fiber",
    "ftth",
    "telefonica",
    "movistar",
    "orange",
    "vodafone",
    "masmovil",
    "másmóvil",
    "jazztel",
    "yoigo",
    "digi",
    "lowi",
    "finetwork",
)

RISK_PORTS = {
    23: ("HIGH", "Telnet exposed"),
    5900: ("HIGH", "VNC exposed"),
    5901: ("HIGH", "VNC exposed"),
    5902: ("HIGH", "VNC exposed"),
    5903: ("HIGH", "VNC exposed"),
    3389: ("HIGH", "RDP exposed"),
    502: ("HIGH", "Modbus/TCP exposed"),
    102: ("HIGH", "S7Comm exposed"),
    47808: ("HIGH", "BACnet/IP exposed"),
    44818: ("HIGH", "EtherNet/IP exposed"),
    20000: ("HIGH", "DNP3 exposed"),
    20256: ("HIGH", "Unitronics PCOM exposed"),
    1962: ("HIGH", "PC Worx/industrial protocol exposed"),
    2455: ("MEDIUM", "CODESYS-related service exposed"),
    11740: ("MEDIUM", "CODESYS-related service exposed"),
    21: ("MEDIUM", "FTP exposed"),
    22: ("MEDIUM", "SSH exposed"),
    80: ("MEDIUM", "HTTP exposed"),
    443: ("MEDIUM", "HTTPS exposed"),
    8080: ("MEDIUM", "HTTP admin-like port exposed"),
    8443: ("MEDIUM", "HTTPS admin-like port exposed"),
}

RISK_RANK = {"LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}
RISK_COLORS = {
    "CRITICAL": "#7f1d1d",
    "HIGH": "#dc2626",
    "MEDIUM": "#f59e0b",
    "LOW": "#2563eb",
}


def _client() -> tuple[SDK, str]:
    org_id = os.environ.get("CENSYS_ORG_ID", "")
    token = os.environ.get("CENSYS_PAT", "")
    if not org_id or not token:
        raise SystemExit("Set CENSYS_ORG_ID and CENSYS_PAT before running this script.")
    return SDK(organization_id=org_id, personal_access_token=token), org_id


def _asn_name(host: dict[str, Any]) -> str:
    asn = host.get("autonomous_system") or {}
    return " ".join(
        str(asn.get(key, ""))
        for key in ("name", "description", "organization")
        if asn.get(key)
    )


def _is_cloud_or_residential(host: dict[str, Any]) -> tuple[bool, str]:
    name = _asn_name(host).lower()
    for term in CLOUD_ASN_TERMS:
        if term in name:
            return True, f"cloud ASN heuristic: {term}"
    for term in RESIDENTIAL_ASN_TERMS:
        if term in name:
            return True, f"residential ISP heuristic: {term}"
    return False, ""


def _labels(service: dict[str, Any]) -> list[str]:
    values: list[str] = []
    for label in service.get("labels", []) or []:
        if isinstance(label, dict) and label.get("value"):
            values.append(str(label["value"]))
    return sorted(set(values))


def _service_name(service: dict[str, Any]) -> str:
    port = service.get("port")
    protocol = service.get("protocol") or service.get("transport_protocol") or ""
    label_text = "/".join(_labels(service))
    parts = [str(x) for x in (port, protocol, label_text) if x]
    return " ".join(parts)


def _service_text(host: dict[str, Any]) -> str:
    compact = {
        "dns": host.get("dns"),
        "asn": host.get("autonomous_system"),
        "services": [
            {
                "port": s.get("port"),
                "protocol": s.get("protocol"),
                "labels": s.get("labels"),
                "software": s.get("software"),
                "hardware": s.get("hardware"),
                "http": s.get("http"),
            }
            for s in host.get("services", []) or []
        ],
    }
    return json.dumps(compact, ensure_ascii=False, sort_keys=True).lower()


def _risk_for_host(host: dict[str, Any]) -> tuple[str, list[str], list[str]]:
    services = host.get("services", []) or []
    reasons: list[str] = []
    service_summaries: list[str] = []
    level = "LOW"
    has_ics_label = False
    has_remote_admin = False
    has_industrial_protocol = False

    for service in services:
        service_summaries.append(_service_name(service))
        labels = {label.upper() for label in _labels(service)}
        if labels & {"ICS", "SCADA", "INDUSTRIAL_CONTROL", "ELECTRICAL", "WATER", "OIL_AND_GAS"}:
            has_ics_label = True
        port = service.get("port")
        if not isinstance(port, int):
            continue
        risk = RISK_PORTS.get(port)
        if risk:
            risk_level, reason = risk
            reasons.append(reason)
            if RISK_RANK[risk_level] > RISK_RANK[level]:
                level = risk_level
        if port in {23, 3389, 5900, 5901, 5902, 5903}:
            has_remote_admin = True
        if port in {502, 102, 47808, 44818, 20000, 20256, 1962, 2455, 11740}:
            has_industrial_protocol = True

    text = _service_text(host)
    if "vnc" in text:
        has_remote_admin = True
        reasons.append("VNC metadata detected")
    if "telnet" in text:
        has_remote_admin = True
        reasons.append("Telnet metadata detected")
    if "modbus" in text or "s7" in text or "bacnet" in text or "ethernet/ip" in text:
        has_industrial_protocol = True

    if has_remote_admin and (has_ics_label or has_industrial_protocol):
        level = "CRITICAL"
        reasons.append("Remote administration exposed on an industrial/ICS candidate")
    elif has_industrial_protocol and RISK_RANK[level] < RISK_RANK["HIGH"]:
        level = "HIGH"
        reasons.append("Industrial protocol exposed")
    elif has_ics_label and RISK_RANK[level] < RISK_RANK["MEDIUM"]:
        level = "MEDIUM"
        reasons.append("Censys industrial label present")

    clean_services = sorted(set(s for s in service_summaries if s))
    clean_reasons = sorted(set(reasons))
    return level, clean_reasons, clean_services


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


def _rows(hosts: list[dict[str, Any]], salt: str, exclude_consumer_networks: bool) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for host in hosts:
        excluded, exclusion_reason = _is_cloud_or_residential(host)
        if exclude_consumer_networks and excluded:
            continue
        location = host.get("location") or {}
        coords = location.get("coordinates") or {}
        lat = coords.get("latitude")
        lon = coords.get("longitude")
        if lat is None or lon is None:
            continue
        risk, reasons, services = _risk_for_host(host)
        ip = str(host.get("ip", ""))
        rows.append(
            {
                "id": _anon_id(ip, salt),
                "risk": risk,
                "city": location.get("city", ""),
                "province": location.get("province", ""),
                "country_code": location.get("country_code", ""),
                "latitude": lat,
                "longitude": lon,
                "asn": _asn_name(host),
                "service_count": host.get("service_count", len(host.get("services", []))),
                "exposed_services": "; ".join(services[:14]),
                "risk_reasons": "; ".join(reasons),
                "filtered_network_note": exclusion_reason,
            }
        )
    return sorted(rows, key=lambda r: (-RISK_RANK.get(str(r["risk"]), 0), str(r["city"])))


def _html(rows: list[dict[str, Any]], query: str, generated_at: str) -> str:
    markers = json.dumps(rows, ensure_ascii=False)
    counts = {level: sum(1 for row in rows if row["risk"] == level) for level in RISK_RANK}
    table_rows = "\n".join(
        "<tr>"
        f"<td><span class='pill {escape(str(row['risk']).lower())}'>{escape(str(row['risk']))}</span></td>"
        f"<td>{escape(str(row['id']))}</td>"
        f"<td>{escape(str(row['city']))}</td>"
        f"<td>{escape(str(row['risk_reasons']))}</td>"
        f"<td>{escape(str(row['exposed_services']))}</td>"
        "</tr>"
        for row in rows[:80]
    )
    return f"""<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Andalusia Industrial Exposure Risk Map</title>
  <link rel="stylesheet" href="https://unpkg.com/leaflet@1.9.4/dist/leaflet.css">
  <script src="https://unpkg.com/leaflet@1.9.4/dist/leaflet.js"></script>
  <style>
    body {{ margin: 0; font-family: Inter, system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif; color: #172033; background: #f6f8fb; }}
    header {{ padding: 22px 28px 12px; }}
    h1 {{ margin: 0 0 8px; font-size: 26px; }}
    p {{ margin: 6px 0; line-height: 1.45; }}
    code {{ background: #edf1f6; padding: 2px 5px; border-radius: 4px; }}
    .wrap {{ display: grid; grid-template-columns: minmax(0, 1fr) 520px; gap: 16px; padding: 0 20px 20px; }}
    #map {{ min-height: 650px; height: 76vh; border-radius: 8px; border: 1px solid #dbe2eb; }}
    .panel {{ background: white; border: 1px solid #dbe2eb; border-radius: 8px; padding: 14px; overflow: auto; }}
    .meta {{ color: #536273; font-size: 14px; }}
    .stats {{ display: flex; gap: 8px; flex-wrap: wrap; margin-top: 10px; }}
    .pill {{ display: inline-block; border-radius: 999px; padding: 3px 8px; color: white; font-size: 12px; font-weight: 700; }}
    .critical {{ background: #7f1d1d; }}
    .high {{ background: #dc2626; }}
    .medium {{ background: #f59e0b; color: #231a00; }}
    .low {{ background: #2563eb; }}
    table {{ width: 100%; border-collapse: collapse; font-size: 13px; }}
    th, td {{ border-bottom: 1px solid #e7edf5; padding: 7px; text-align: left; vertical-align: top; }}
    @media (max-width: 1100px) {{ .wrap {{ grid-template-columns: 1fr; }} #map {{ height: 62vh; min-height: 460px; }} }}
  </style>
</head>
<body>
  <header>
    <h1>Andalusia Industrial Exposure Risk Map</h1>
    <p class="meta">Generated: {generated_at}. Anonymized candidates mapped: <strong>{len(rows)}</strong>. Full IP addresses are not stored in the output.</p>
    <p class="meta">Passive Censys query: <code>{escape(query)}</code></p>
    <p class="meta">Risk is heuristic: exposed remote administration, industrial protocols, and Censys labels. It does not prove exploitation or unauthorized access.</p>
    <div class="stats">
      <span class="pill critical">Critical {counts.get("CRITICAL", 0)}</span>
      <span class="pill high">High {counts.get("HIGH", 0)}</span>
      <span class="pill medium">Medium {counts.get("MEDIUM", 0)}</span>
      <span class="pill low">Low {counts.get("LOW", 0)}</span>
    </div>
  </header>
  <main class="wrap">
    <section><div id="map"></div></section>
    <aside class="panel">
      <h2>Findings</h2>
      <table>
        <thead><tr><th>Risk</th><th>ID</th><th>City</th><th>Reason</th><th>Services</th></tr></thead>
        <tbody>{table_rows}</tbody>
      </table>
    </aside>
  </main>
  <script>
    const rows = {markers};
    const riskColors = {json.dumps(RISK_COLORS)};
    const riskRadius = {{ CRITICAL: 10, HIGH: 8, MEDIUM: 7, LOW: 6 }};
    const map = L.map("map").setView([37.45, -4.7], 7);
    L.tileLayer("https://{{s}}.tile.openstreetmap.org/{{z}}/{{x}}/{{y}}.png", {{
      maxZoom: 18,
      attribution: "&copy; OpenStreetMap contributors"
    }}).addTo(map);

    const group = L.featureGroup().addTo(map);
    for (const row of rows) {{
      const color = riskColors[row.risk] || "#2563eb";
      const marker = L.circleMarker([row.latitude, row.longitude], {{
        radius: riskRadius[row.risk] || 6,
        color,
        fillColor: color,
        fillOpacity: 0.72,
        weight: 1
      }});
      marker.bindPopup(`
        <strong>${{row.risk}}</strong> - ${{row.city || "Unknown city"}}<br>
        Anonymized ID: ${{row.id}}<br>
        ASN: ${{row.asn || "Unknown"}}<br>
        Reasons: ${{row.risk_reasons || "n/a"}}<br>
        Services: <small>${{row.exposed_services || "n/a"}}</small>
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
    parser = argparse.ArgumentParser(
        description="Generate an anonymized industry exposure risk map for Andalusia using Censys."
    )
    parser.add_argument("--query", default=DEFAULT_QUERY, help="CenQL query to execute")
    parser.add_argument("--max", type=int, default=300, help="Maximum hosts to retrieve")
    parser.add_argument("--page-size", type=int, default=50, help="Censys page size")
    parser.add_argument("--pause", type=float, default=1.0, help="Pause between pages")
    parser.add_argument(
        "--include-consumer-networks",
        action="store_true",
        help="Do not filter common residential/cloud ASN heuristics",
    )
    args = parser.parse_args()

    hosts = _collect(args.query, max_records=args.max, page_size=args.page_size, pause=args.pause)
    salt = os.environ.get("ANON_SALT", "andalucia-industry-risk")
    rows = _rows(
        hosts,
        salt=salt,
        exclude_consumer_networks=not args.include_consumer_networks,
    )
    generated_at = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")

    out_dir = Path("output")
    out_dir.mkdir(parents=True, exist_ok=True)
    html_path = out_dir / "andalucia_industry_risk_map.html"
    csv_path = out_dir / "andalucia_industry_risk_findings.csv"
    json_path = out_dir / "andalucia_industry_risk_findings.json"

    fieldnames = [
        "id",
        "risk",
        "city",
        "province",
        "country_code",
        "latitude",
        "longitude",
        "asn",
        "service_count",
        "exposed_services",
        "risk_reasons",
        "filtered_network_note",
    ]
    with csv_path.open("w", encoding="utf-8", newline="") as fh:
        writer = csv.DictWriter(fh, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(rows)

    json_path.write_text(
        json.dumps(
            {
                "query": args.query,
                "generated_at": generated_at,
                "hosts_retrieved": len(hosts),
                "findings_mapped": len(rows),
                "consumer_networks_filtered": not args.include_consumer_networks,
                "risk_model": {
                    "critical": "Remote administration exposed on an industrial/ICS candidate",
                    "high": "Industrial protocol or high-risk remote service exposed",
                    "medium": "Potentially sensitive service or Censys industrial label",
                    "low": "Matched query but no stronger risk signal",
                },
                "rows": rows,
            },
            ensure_ascii=False,
            indent=2,
        ),
        encoding="utf-8",
    )
    html_path.write_text(_html(rows, args.query, generated_at), encoding="utf-8")

    print(f"hosts_retrieved={len(hosts)}")
    print(f"findings_mapped={len(rows)}")
    print(f"html={html_path}")
    print(f"csv={csv_path}")
    print(f"json={json_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
