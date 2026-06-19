#!/usr/bin/env python3
"""Interfaz de línea de comandos del ICS-OSINT Toolkit.

Cada subcomando corresponde a una fase de la metodología  y produce un
artefacto JSON intermedio, de modo que las fases que no requieren red (filtrado,
correlación con catálogo semilla, agregación, informe) pueden ejecutarse de
forma independiente y reproducible.

Uso:
    python cli.py collect    --config config/config.yaml --queries config/queries.yaml
    python cli.py filter     --config config/config.yaml
    python cli.py correlate  --config config/config.yaml [--nvd] [--kev]
    python cli.py report     --config config/config.yaml
    python cli.py all        --config config/config.yaml --queries config/queries.yaml

Recordatorio: toda la recolección es PASIVA. No se conecta a ningún sistema
identificado.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from ics_osint import config as cfgmod
from ics_osint import aggregate, cve_correlation, filters, report
from ics_osint.censys_client import CensysPassiveClient, load_raw_dir, save_raw
from ics_osint.nvd_client import NvdClient


def _safe_id(qid: str) -> str:
    return "".join(c if c.isalnum() or c in "-_" else "_" for c in qid)


# --------------------------------------------------------------------------- #
# Fase 3 — Recolección
# --------------------------------------------------------------------------- #
def cmd_collect(args: argparse.Namespace) -> int:
    cfg = cfgmod.load_config(args.config)
    cfg.paths.ensure()
    queries = cfgmod.load_queries(args.queries)
    client = CensysPassiveClient(
        cfg.censys_org_id, cfg.censys_token, page_size=cfg.censys_page_size
    )
    max_records = args.max or cfg.default_max_records
    counts = []
    for q in queries:
        print(f"[collect] {q['id']} ({q['region']}) ...", flush=True)
        if args.count_only:
            total = client.count(q["cenql"])
            result = {"query": q["cenql"], "total": total, "retrieved": 0, "hosts": []}
        else:
            result = client.collect(q["cenql"], max_records=max_records)
        result.update({"id": q["id"], "region": q["region"], "description": q["description"]})
        save_raw(result, cfg.paths.raw_dir / f"{_safe_id(q['id'])}.json")
        counts.append(
            {
                "id": q["id"],
                "region": q["region"],
                "description": q["description"],
                "total": result.get("total"),
                "retrieved": result.get("retrieved", 0),
            }
        )
    (cfg.paths.base / "counts.json").write_text(
        json.dumps(counts, ensure_ascii=False, indent=2), encoding="utf-8"
    )
    report.write_counts_csv(counts, cfg.paths.output_dir / "counts.csv")
    print(f"[collect] {len(queries)} consultas guardadas en {cfg.paths.raw_dir}")
    return 0


# --------------------------------------------------------------------------- #
# Fase 4 — Filtrado
# --------------------------------------------------------------------------- #
def cmd_filter(args: argparse.Namespace) -> int:
    cfg = cfgmod.load_config(args.config)
    cfg.paths.ensure()
    all_hosts: list[dict] = []
    excluded_total = 0
    for raw in load_raw_dir(cfg.paths.raw_dir):
        hosts = raw.get("hosts", [])
        res = filters.filter_hosts(
            hosts, cfg.honeypot_labels, cfg.cloud_asn_names, drop_cloud=True
        )
        all_hosts.extend(res["kept"])
        excluded_total += len(res["excluded"])
    clean = filters.dedup_by_ip(all_hosts)
    out = cfg.paths.clean_dir / "clean_all.json"
    out.write_text(json.dumps(clean, ensure_ascii=False, indent=2), encoding="utf-8")
    print(
        f"[filter] {len(clean)} hosts depurados "
        f"(excluidos {excluded_total} falsos positivos) -> {out}"
    )
    return 0


# --------------------------------------------------------------------------- #
# Fase 5 — Correlación
# --------------------------------------------------------------------------- #
def cmd_correlate(args: argparse.Namespace) -> int:
    cfg = cfgmod.load_config(args.config)
    cfg.paths.ensure()
    clean_path = cfg.paths.clean_dir / "clean_all.json"
    if not clean_path.exists():
        print("[correlate] No existe clean_all.json. Ejecuta 'filter' primero.", file=sys.stderr)
        return 1
    hosts = json.loads(clean_path.read_text(encoding="utf-8"))

    seed = cve_correlation.load_seed_catalog(Path("data/cve_seed.yaml"))
    kev: set[str] = set()
    if args.kev:
        kev = cve_correlation.load_kev_catalog(
            cfg.kev_url, cache=cfg.paths.base / "kev_cache.json"
        )
        print(f"[correlate] KEV cargado: {len(kev)} CVEs")
    nvd = None
    if args.nvd:
        nvd = NvdClient(api_key=cfg.nvd_api_key)
        print("[correlate] Correlación con NVD activada"
              f" ({'con' if cfg.nvd_api_key else 'sin'} clave de API)")

    findings = [
        cve_correlation.analyze_host(
            h, seed, kev, nvd=nvd, use_keyword_search=args.keyword
        )
        for h in hosts
    ]
    out = cfg.paths.cve_dir / "findings.json"
    out.write_text(json.dumps(findings, ensure_ascii=False, indent=2), encoding="utf-8")
    crit = sum(1 for f in findings if f["severity"] == "CRÍTICO")
    print(f"[correlate] {len(findings)} hallazgos ({crit} CRÍTICOS) -> {out}")
    return 0


# --------------------------------------------------------------------------- #
# Fases 6–7 — Agregación e informe
# --------------------------------------------------------------------------- #
def cmd_report(args: argparse.Namespace) -> int:
    cfg = cfgmod.load_config(args.config)
    cfg.paths.ensure()
    clean_path = cfg.paths.clean_dir / "clean_all.json"
    findings_path = cfg.paths.cve_dir / "findings.json"
    if not clean_path.exists():
        print("[report] Falta clean_all.json. Ejecuta 'filter' primero.", file=sys.stderr)
        return 1
    hosts = json.loads(clean_path.read_text(encoding="utf-8"))
    findings = (
        json.loads(findings_path.read_text(encoding="utf-8"))
        if findings_path.exists()
        else []
    )

    summary = aggregate.summarize(hosts, cfg.regions)
    sev = aggregate.severity_distribution(findings)
    top = aggregate.top_cves(findings)

    md = report.write_markdown(summary, sev, top, cfg.paths.output_dir / "informe.md")
    anon = cfg.anonymization
    report.write_findings_csv(
        findings,
        cfg.paths.output_dir / "hallazgos.csv",
        anon_method=anon.get("method", "truncate"),
        keep_octets=int(anon.get("keep_octets", 2)),
        salt=anon.get("salt", ""),
    )
    (cfg.paths.output_dir / "summary.json").write_text(
        json.dumps(summary, ensure_ascii=False, indent=2), encoding="utf-8"
    )
    print(f"[report] Informe generado -> {md}")
    print(f"[report] CSV y summary.json en {cfg.paths.output_dir}")
    return 0


def cmd_all(args: argparse.Namespace) -> int:
    for fn in (cmd_collect, cmd_filter, cmd_correlate, cmd_report):
        rc = fn(args)
        if rc != 0:
            return rc
    return 0


# --------------------------------------------------------------------------- #
def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(description="ICS-OSINT Toolkit (OSINT pasivo)")
    sub = p.add_subparsers(dest="command", required=True)

    common = argparse.ArgumentParser(add_help=False)
    common.add_argument("--config", default="config/config.yaml", help="Ruta a config.yaml")

    c = sub.add_parser("collect", parents=[common], help="Fase 3: recolección Censys")
    c.add_argument("--queries", default="config/queries.yaml")
    c.add_argument("--max", type=int, default=0, help="Máx. hosts por consulta")
    c.add_argument("--count-only", action="store_true", help="Solo contadores totales")
    c.set_defaults(func=cmd_collect)

    f = sub.add_parser("filter", parents=[common], help="Fase 4: filtrado/depuración")
    f.set_defaults(func=cmd_filter)

    cor = sub.add_parser("correlate", parents=[common], help="Fase 5: correlación CVE")
    cor.add_argument("--nvd", action="store_true", help="Consultar NVD API 2.0")
    cor.add_argument("--kev", action="store_true", help="Descargar catálogo KEV de CISA")
    cor.add_argument("--keyword", action="store_true", help="Búsqueda NVD por palabra clave")
    cor.set_defaults(func=cmd_correlate)

    r = sub.add_parser("report", parents=[common], help="Fases 6–7: agregación e informe")
    r.set_defaults(func=cmd_report)

    a = sub.add_parser("all", parents=[common], help="Pipeline completo")
    a.add_argument("--queries", default="config/queries.yaml")
    a.add_argument("--max", type=int, default=0)
    a.add_argument("--count-only", action="store_true")
    a.add_argument("--nvd", action="store_true")
    a.add_argument("--kev", action="store_true")
    a.add_argument("--keyword", action="store_true")
    a.set_defaults(func=cmd_all)

    return p


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
