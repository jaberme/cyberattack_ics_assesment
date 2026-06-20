#!/usr/bin/env python3
"""Generate a passive Censys world choropleth for exposed ICS-like surfaces."""

from __future__ import annotations

import csv
import json
import os
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from censys_platform import SDK

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from ics_osint.censys_client import _to_plain


QUERY = (
    '(host.services.labels.value: {"ICS", "ELECTRICAL", "OIL_AND_GAS"}) '
    'and not host.services.labels.value = "HONEYPOT"'
)

ISO2_TO_ISO3_NAME = {
    "AD": ("AND", "Andorra"), "AE": ("ARE", "United Arab Emirates"), "AF": ("AFG", "Afghanistan"),
    "AG": ("ATG", "Antigua and Barbuda"), "AI": ("AIA", "Anguilla"), "AL": ("ALB", "Albania"),
    "AM": ("ARM", "Armenia"), "AO": ("AGO", "Angola"), "AQ": ("ATA", "Antarctica"),
    "AR": ("ARG", "Argentina"), "AS": ("ASM", "American Samoa"), "AT": ("AUT", "Austria"),
    "AU": ("AUS", "Australia"), "AW": ("ABW", "Aruba"), "AX": ("ALA", "Aland Islands"),
    "AZ": ("AZE", "Azerbaijan"), "BA": ("BIH", "Bosnia and Herzegovina"), "BB": ("BRB", "Barbados"),
    "BD": ("BGD", "Bangladesh"), "BE": ("BEL", "Belgium"), "BF": ("BFA", "Burkina Faso"),
    "BG": ("BGR", "Bulgaria"), "BH": ("BHR", "Bahrain"), "BI": ("BDI", "Burundi"),
    "BJ": ("BEN", "Benin"), "BL": ("BLM", "Saint Barthelemy"), "BM": ("BMU", "Bermuda"),
    "BN": ("BRN", "Brunei Darussalam"), "BO": ("BOL", "Bolivia"), "BQ": ("BES", "Bonaire, Sint Eustatius and Saba"),
    "BR": ("BRA", "Brazil"), "BS": ("BHS", "Bahamas"), "BT": ("BTN", "Bhutan"),
    "BV": ("BVT", "Bouvet Island"), "BW": ("BWA", "Botswana"), "BY": ("BLR", "Belarus"),
    "BZ": ("BLZ", "Belize"), "CA": ("CAN", "Canada"), "CC": ("CCK", "Cocos Islands"),
    "CD": ("COD", "Democratic Republic of the Congo"), "CF": ("CAF", "Central African Republic"),
    "CG": ("COG", "Republic of the Congo"), "CH": ("CHE", "Switzerland"), "CI": ("CIV", "Cote d'Ivoire"),
    "CK": ("COK", "Cook Islands"), "CL": ("CHL", "Chile"), "CM": ("CMR", "Cameroon"),
    "CN": ("CHN", "China"), "CO": ("COL", "Colombia"), "CR": ("CRI", "Costa Rica"),
    "CU": ("CUB", "Cuba"), "CV": ("CPV", "Cabo Verde"), "CW": ("CUW", "Curacao"),
    "CX": ("CXR", "Christmas Island"), "CY": ("CYP", "Cyprus"), "CZ": ("CZE", "Czechia"),
    "DE": ("DEU", "Germany"), "DJ": ("DJI", "Djibouti"), "DK": ("DNK", "Denmark"),
    "DM": ("DMA", "Dominica"), "DO": ("DOM", "Dominican Republic"), "DZ": ("DZA", "Algeria"),
    "EC": ("ECU", "Ecuador"), "EE": ("EST", "Estonia"), "EG": ("EGY", "Egypt"),
    "EH": ("ESH", "Western Sahara"), "ER": ("ERI", "Eritrea"), "ES": ("ESP", "Spain"),
    "ET": ("ETH", "Ethiopia"), "FI": ("FIN", "Finland"), "FJ": ("FJI", "Fiji"),
    "FK": ("FLK", "Falkland Islands"), "FM": ("FSM", "Micronesia"), "FO": ("FRO", "Faroe Islands"),
    "FR": ("FRA", "France"), "GA": ("GAB", "Gabon"), "GB": ("GBR", "United Kingdom"),
    "GD": ("GRD", "Grenada"), "GE": ("GEO", "Georgia"), "GF": ("GUF", "French Guiana"),
    "GG": ("GGY", "Guernsey"), "GH": ("GHA", "Ghana"), "GI": ("GIB", "Gibraltar"),
    "GL": ("GRL", "Greenland"), "GM": ("GMB", "Gambia"), "GN": ("GIN", "Guinea"),
    "GP": ("GLP", "Guadeloupe"), "GQ": ("GNQ", "Equatorial Guinea"), "GR": ("GRC", "Greece"),
    "GS": ("SGS", "South Georgia and the South Sandwich Islands"), "GT": ("GTM", "Guatemala"),
    "GU": ("GUM", "Guam"), "GW": ("GNB", "Guinea-Bissau"), "GY": ("GUY", "Guyana"),
    "HK": ("HKG", "Hong Kong"), "HM": ("HMD", "Heard Island and McDonald Islands"),
    "HN": ("HND", "Honduras"), "HR": ("HRV", "Croatia"), "HT": ("HTI", "Haiti"),
    "HU": ("HUN", "Hungary"), "ID": ("IDN", "Indonesia"), "IE": ("IRL", "Ireland"),
    "IL": ("ISR", "Israel"), "IM": ("IMN", "Isle of Man"), "IN": ("IND", "India"),
    "IO": ("IOT", "British Indian Ocean Territory"), "IQ": ("IRQ", "Iraq"), "IR": ("IRN", "Iran"),
    "IS": ("ISL", "Iceland"), "IT": ("ITA", "Italy"), "JE": ("JEY", "Jersey"),
    "JM": ("JAM", "Jamaica"), "JO": ("JOR", "Jordan"), "JP": ("JPN", "Japan"),
    "KE": ("KEN", "Kenya"), "KG": ("KGZ", "Kyrgyzstan"), "KH": ("KHM", "Cambodia"),
    "KI": ("KIR", "Kiribati"), "KM": ("COM", "Comoros"), "KN": ("KNA", "Saint Kitts and Nevis"),
    "KP": ("PRK", "North Korea"), "KR": ("KOR", "South Korea"), "KW": ("KWT", "Kuwait"),
    "KY": ("CYM", "Cayman Islands"), "KZ": ("KAZ", "Kazakhstan"), "LA": ("LAO", "Laos"),
    "LB": ("LBN", "Lebanon"), "LC": ("LCA", "Saint Lucia"), "LI": ("LIE", "Liechtenstein"),
    "LK": ("LKA", "Sri Lanka"), "LR": ("LBR", "Liberia"), "LS": ("LSO", "Lesotho"),
    "LT": ("LTU", "Lithuania"), "LU": ("LUX", "Luxembourg"), "LV": ("LVA", "Latvia"),
    "LY": ("LBY", "Libya"), "MA": ("MAR", "Morocco"), "MC": ("MCO", "Monaco"),
    "MD": ("MDA", "Moldova"), "ME": ("MNE", "Montenegro"), "MF": ("MAF", "Saint Martin"),
    "MG": ("MDG", "Madagascar"), "MH": ("MHL", "Marshall Islands"), "MK": ("MKD", "North Macedonia"),
    "ML": ("MLI", "Mali"), "MM": ("MMR", "Myanmar"), "MN": ("MNG", "Mongolia"),
    "MO": ("MAC", "Macao"), "MP": ("MNP", "Northern Mariana Islands"), "MQ": ("MTQ", "Martinique"),
    "MR": ("MRT", "Mauritania"), "MS": ("MSR", "Montserrat"), "MT": ("MLT", "Malta"),
    "MU": ("MUS", "Mauritius"), "MV": ("MDV", "Maldives"), "MW": ("MWI", "Malawi"),
    "MX": ("MEX", "Mexico"), "MY": ("MYS", "Malaysia"), "MZ": ("MOZ", "Mozambique"),
    "NA": ("NAM", "Namibia"), "NC": ("NCL", "New Caledonia"), "NE": ("NER", "Niger"),
    "NF": ("NFK", "Norfolk Island"), "NG": ("NGA", "Nigeria"), "NI": ("NIC", "Nicaragua"),
    "NL": ("NLD", "Netherlands"), "NO": ("NOR", "Norway"), "NP": ("NPL", "Nepal"),
    "NR": ("NRU", "Nauru"), "NU": ("NIU", "Niue"), "NZ": ("NZL", "New Zealand"),
    "OM": ("OMN", "Oman"), "PA": ("PAN", "Panama"), "PE": ("PER", "Peru"),
    "PF": ("PYF", "French Polynesia"), "PG": ("PNG", "Papua New Guinea"), "PH": ("PHL", "Philippines"),
    "PK": ("PAK", "Pakistan"), "PL": ("POL", "Poland"), "PM": ("SPM", "Saint Pierre and Miquelon"),
    "PN": ("PCN", "Pitcairn"), "PR": ("PRI", "Puerto Rico"), "PS": ("PSE", "Palestine"),
    "PT": ("PRT", "Portugal"), "PW": ("PLW", "Palau"), "PY": ("PRY", "Paraguay"),
    "QA": ("QAT", "Qatar"), "RE": ("REU", "Reunion"), "RO": ("ROU", "Romania"),
    "RS": ("SRB", "Serbia"), "RU": ("RUS", "Russia"), "RW": ("RWA", "Rwanda"),
    "SA": ("SAU", "Saudi Arabia"), "SB": ("SLB", "Solomon Islands"), "SC": ("SYC", "Seychelles"),
    "SD": ("SDN", "Sudan"), "SE": ("SWE", "Sweden"), "SG": ("SGP", "Singapore"),
    "SH": ("SHN", "Saint Helena"), "SI": ("SVN", "Slovenia"), "SJ": ("SJM", "Svalbard and Jan Mayen"),
    "SK": ("SVK", "Slovakia"), "SL": ("SLE", "Sierra Leone"), "SM": ("SMR", "San Marino"),
    "SN": ("SEN", "Senegal"), "SO": ("SOM", "Somalia"), "SR": ("SUR", "Suriname"),
    "SS": ("SSD", "South Sudan"), "ST": ("STP", "Sao Tome and Principe"), "SV": ("SLV", "El Salvador"),
    "SX": ("SXM", "Sint Maarten"), "SY": ("SYR", "Syria"), "SZ": ("SWZ", "Eswatini"),
    "TC": ("TCA", "Turks and Caicos Islands"), "TD": ("TCD", "Chad"), "TF": ("ATF", "French Southern Territories"),
    "TG": ("TGO", "Togo"), "TH": ("THA", "Thailand"), "TJ": ("TJK", "Tajikistan"),
    "TK": ("TKL", "Tokelau"), "TL": ("TLS", "Timor-Leste"), "TM": ("TKM", "Turkmenistan"),
    "TN": ("TUN", "Tunisia"), "TO": ("TON", "Tonga"), "TR": ("TUR", "Turkey"),
    "TT": ("TTO", "Trinidad and Tobago"), "TV": ("TUV", "Tuvalu"), "TW": ("TWN", "Taiwan"),
    "TZ": ("TZA", "Tanzania"), "UA": ("UKR", "Ukraine"), "UG": ("UGA", "Uganda"),
    "UM": ("UMI", "United States Minor Outlying Islands"), "US": ("USA", "United States"),
    "UY": ("URY", "Uruguay"), "UZ": ("UZB", "Uzbekistan"), "VA": ("VAT", "Holy See"),
    "VC": ("VCT", "Saint Vincent and the Grenadines"), "VE": ("VEN", "Venezuela"),
    "VG": ("VGB", "British Virgin Islands"), "VI": ("VIR", "U.S. Virgin Islands"),
    "VN": ("VNM", "Vietnam"), "VU": ("VUT", "Vanuatu"), "WF": ("WLF", "Wallis and Futuna"),
    "WS": ("WSM", "Samoa"), "YE": ("YEM", "Yemen"), "YT": ("MYT", "Mayotte"),
    "ZA": ("ZAF", "South Africa"), "ZM": ("ZMB", "Zambia"), "ZW": ("ZWE", "Zimbabwe"),
}


def _extract_aggregate(payload: dict[str, Any]) -> dict[str, Any]:
    node = payload
    for key in ("result", "result"):
        node = node.get(key, {})
    return node


def _html(rows: list[dict[str, Any]], total: int, other: int, generated_at: str) -> str:
    plot_rows = [r for r in rows if r["iso3"]]
    top_rows = sorted(rows, key=lambda r: r["count"], reverse=True)[:15]
    table = "\n".join(
        f"<tr><td>{r['country_name']}</td><td>{r['country_code']}</td><td>{r['count']:,}</td></tr>"
        for r in top_rows
    )
    payload = json.dumps(plot_rows, ensure_ascii=False)
    query = json.dumps(QUERY, ensure_ascii=False)
    return f"""<!doctype html>
<html lang="es">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Mapa mundial de superficies ICS/OT expuestas</title>
  <script src="https://cdn.plot.ly/plotly-2.35.2.min.js"></script>
  <style>
    body {{ margin: 0; font-family: Inter, system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif; color: #172033; background: #f7f8fb; }}
    header {{ padding: 24px 32px 12px; }}
    h1 {{ margin: 0 0 8px; font-size: 26px; font-weight: 750; }}
    p {{ margin: 6px 0; line-height: 1.45; }}
    code {{ background: #eef1f6; padding: 2px 5px; border-radius: 4px; }}
    #map {{ height: 72vh; min-height: 520px; }}
    .meta {{ color: #516070; font-size: 14px; }}
    .wrap {{ display: grid; grid-template-columns: minmax(0, 1fr) 360px; gap: 18px; padding: 0 24px 24px; }}
    .panel {{ background: white; border: 1px solid #dde3ec; border-radius: 8px; padding: 16px; }}
    table {{ width: 100%; border-collapse: collapse; font-size: 14px; }}
    th, td {{ border-bottom: 1px solid #e8edf4; padding: 8px; text-align: left; }}
    th:last-child, td:last-child {{ text-align: right; }}
    @media (max-width: 900px) {{ .wrap {{ grid-template-columns: 1fr; }} #map {{ height: 60vh; }} }}
  </style>
</head>
<body>
  <header>
    <h1>Distribución mundial de superficies ICS/OT expuestas</h1>
    <p class="meta">Consulta pasiva Censys agregada por país. Generado: {generated_at}. Total: <strong>{total:,}</strong>. Otros/no mapeados: <strong>{other:,}</strong>.</p>
    <p class="meta">Consulta: <code>{QUERY}</code></p>
  </header>
  <main class="wrap">
    <section class="panel"><div id="map"></div></section>
    <aside class="panel">
      <h2>Top 15 países</h2>
      <table>
        <thead><tr><th>País</th><th>ISO2</th><th>Hosts</th></tr></thead>
        <tbody>{table}</tbody>
      </table>
      <p class="meta">Nota: son superficies expuestas indexadas por Censys con etiquetas ICS, ELECTRICAL u OIL_AND_GAS, excluyendo HONEYPOT. No implica explotación confirmada.</p>
    </aside>
  </main>
  <script>
    const rows = {payload};
    const query = {query};
    const data = [{{
      type: "choropleth",
      locationmode: "ISO-3",
      locations: rows.map(r => r.iso3),
      z: rows.map(r => r.count),
      text: rows.map(r => `${{r.country_name}} (${{r.country_code}}): ${{r.count.toLocaleString()}}`),
      colorscale: "YlOrRd",
      marker: {{ line: {{ color: "rgb(245,245,245)", width: 0.5 }} }},
      colorbar: {{ title: "Hosts" }},
      hovertemplate: "%{{text}}<extra></extra>"
    }}];
    const layout = {{
      margin: {{ l: 0, r: 0, t: 0, b: 0 }},
      paper_bgcolor: "#ffffff",
      geo: {{
        projection: {{ type: "natural earth" }},
        showframe: false,
        showcoastlines: true,
        coastlinecolor: "#9aa6b2",
        landcolor: "#eef1f6",
        bgcolor: "#ffffff"
      }}
    }};
    Plotly.newPlot("map", data, layout, {{ responsive: true, displayModeBar: true }});
  </script>
</body>
</html>
"""


def main() -> int:
    org_id = os.environ.get("CENSYS_ORG_ID", "0af95a0c-2f5f-4fd1-9070-7e5b9af473a3")
    token = os.environ.get("CENSYS_PAT", "censys_XSuLmTDU_JFnaxcjoCjmqeWwEL8tEzSsX")
    if not org_id or not token:
        raise SystemExit("Define CENSYS_ORG_ID y CENSYS_PAT antes de ejecutar.")

    sdk = SDK(organization_id=org_id, personal_access_token=token)
    response = sdk.global_data.aggregate(
        search_aggregate_input_body={
            "query": QUERY,
            "field": "host.location.country_code",
            "number_of_buckets": 250,
            "count_by_level": ".",
            "filter_by_query": True,
        },
        organization_id=org_id,
        timeout_ms=60000,
    )
    payload = _to_plain(response)
    aggregate = _extract_aggregate(payload)
    buckets = aggregate.get("buckets") or []
    total = int(aggregate.get("total_count") or sum(b.get("count", 0) for b in buckets))
    other = int(aggregate.get("other_count") or 0)
    generated_at = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")

    rows: list[dict[str, Any]] = []
    for bucket in sorted(buckets, key=lambda b: b.get("count", 0), reverse=True):
        code = str(bucket.get("key") or "").upper()
        iso3, name = ISO2_TO_ISO3_NAME.get(code, ("", code or "Unknown"))
        rows.append(
            {
                "country_code": code,
                "iso3": iso3,
                "country_name": name,
                "count": int(bucket.get("count") or 0),
            }
        )

    out_dir = Path("output")
    out_dir.mkdir(parents=True, exist_ok=True)
    csv_path = out_dir / "world_ics_surface_counts.csv"
    html_path = out_dir / "world_ics_surface_map.html"
    json_path = out_dir / "world_ics_surface_counts.json"

    with csv_path.open("w", encoding="utf-8", newline="") as fh:
        writer = csv.DictWriter(fh, fieldnames=["country_code", "iso3", "country_name", "count"])
        writer.writeheader()
        writer.writerows(rows)

    json_path.write_text(
        json.dumps(
            {
                "query": QUERY,
                "generated_at": generated_at,
                "total_count": total,
                "other_count": other,
                "rows": rows,
            },
            ensure_ascii=False,
            indent=2,
        ),
        encoding="utf-8",
    )
    html_path.write_text(_html(rows, total, other, generated_at), encoding="utf-8")

    print(f"query={QUERY}")
    print(f"total_count={total}")
    print(f"countries={len(rows)}")
    print(f"other_count={other}")
    print(f"html={html_path}")
    print(f"csv={csv_path}")
    print(f"json={json_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
