# Instrucciones de replicación — ICS-OSINT Toolkit

Guía paso a paso para **reproducir desde la línea de comandos** todos los ensayos
realizados durante la creación y validación del toolkit. Cada experimento indica
su **objetivo**, el **comando exacto** y el **resultado esperado**.

> **Nota sobre las cifras:** el índice de Censys cambia a diario. Los totales que
> aquí se indican son los observados en **junio de 2026** y sirven de orden de
> magnitud, no de valor exacto. Lo reproducible es el *procedimiento* y la *forma*
> de los resultados.

Todos los comandos se ejecutan desde la raíz del toolkit:

```bash
cd ics-osint-toolkit
```

---

## 0. Preparación del entorno (una sola vez)

**Objetivo:** entorno aislado con el SDK y dependencias.

```bash
# Debian/Ubuntu marca el sistema como "externally managed" (PEP 668) -> usar venv
python3 -m venv .venv
.venv/bin/pip install --upgrade pip
.venv/bin/pip install -r requirements.txt
cp config/config.example.yaml config/config.yaml
```

**Verificación esperada:**

```bash
.venv/bin/python -c "import censys_platform, yaml, requests; print(censys_platform.__version__)"
# -> 0.14.3 (o superior)
```

### Credenciales de la Censys Platform (solo para los experimentos en vivo, F3)

```bash
export CENSYS_ORG_ID="<uuid-de-tu-organización>"   # UUID, NO el email
export CENSYS_PAT="censys_xxxxxxxxxxxxxxxxx"        # Personal Access Token
# Opcional:
export NVD_API_KEY="..."
```

> El `organization_id` es un **UUID** (consola de la Platform → Getting Started →
> Step 3). Usar el email da `AuthenticationError: Access credentials are invalid`.
> El PAT es secreto: nunca se versiona (config.yaml lo resuelve desde el entorno).

---

## EXPERIMENTO 1 — Validación offline del pipeline F4→F7 (sin red ni credenciales)

**Objetivo:** comprobar filtrado, correlación y reporte sobre un fixture sintético
(IPs de documentación RFC 5737). Reproduce el informe de referencia de `censys.md §6`.

```bash
# Limpieza previa por si hubiera ejecuciones anteriores
rm -rf data/raw data/clean data/cve output

# F3 simulada: usar el fixture como si fuera una recolección
mkdir -p data/raw && cp samples/raw_sample.json data/raw/muestra.json

.venv/bin/python cli.py filter    --config config/config.yaml
.venv/bin/python cli.py correlate --config config/config.yaml --kev   # --kev necesita red; quítalo para 100% offline
.venv/bin/python cli.py report    --config config/config.yaml

cat output/informe.md
cat output/hallazgos.csv
```

**Resultado esperado:**

```
[filter] 5 hosts depurados (excluidos 2 falsos positivos) -> data/clean/clean_all.json
[correlate] 5 hallazgos (3 CRÍTICOS) -> data/cve/findings.json
[report] Informe generado -> output/informe.md
```

- 5 hosts (2 excluidos: 1 honeypot + 1 cloud sin etiqueta ICS).
- Severidad: 3 CRÍTICO, 1 ALTO, 1 MEDIO.
- CVEs correlacionadas vía catálogo semilla: CVE-2025-40943, CVE-2023-6448 (KEV),
  CVE-2023-3595 (KEV), CVE-2021-22681 (KEV).
- IPs anonimizadas (`192.0.x.x`), organizaciones omitidas.

> Sin conexión a Internet, omite `--kev`: la correlación usa solo el catálogo
> semilla (`data/cve_seed.yaml`) y los CVEs marcados `kev: true` en él.

---

## EXPERIMENTO 2 — Prueba de conectividad F3 (un solo contador)

**Objetivo:** validar credenciales + consulta + extracción del total contra la API
real, con la llamada más barata posible (`--count-only`, una consulta).

```bash
.venv/bin/python cli.py collect --count-only \
    --config config/config.yaml --queries config/queries.test.yaml
cat output/counts.csv
```

**Resultado esperado:** una línea con el total global de Modbus TCP:

```
query_id,region,description,total,retrieved
gl-modbus-test,Global,Total Modbus TCP global (prueba de conectividad),111148,0
```

(El número exacto varía; lo importante es que devuelve un entero y no un error de
autenticación o de consulta.)

---

## EXPERIMENTO 3 — Validación de la sintaxis CenQL de etiquetas

**Objetivo:** confirmar la sintaxis real de las etiquetas honeypot/ICS. Usa contadores directos con el cliente.

```bash
.venv/bin/python - <<'PY'
import os
from ics_osint.censys_client import CensysPassiveClient
c = CensysPassiveClient(os.environ["CENSYS_ORG_ID"], os.environ["CENSYS_PAT"])
tests = [
    ("502 baseline",                  'host.services.port=502'),
    ("502 sin HONEYPOT (servicio)",   'host.services.port=502 and not host.services.labels.value="HONEYPOT"'),
    ("HONEYPOT total",                'host.services.labels.value="HONEYPOT"'),
    ("ICS global (token correcto)",   'host.services.labels.value="ICS"'),
    ("ICS token legacy (incorrecto)", 'host.services.labels.value="INDUSTRIAL_CONTROL_SYSTEM"'),
]
for name, q in tests:
    try:
        print(f"OK   | {name:34} | total={c.count(q)}")
    except Exception as e:
        print(f"FAIL | {name:34} | {str(e)[:90]}")
PY
```

**Resultado esperado:**

```
OK   | 502 baseline                       | total=111148
OK   | 502 sin HONEYPOT (servicio)        | total=109387   (< baseline: el filtro funciona)
OK   | HONEYPOT total                     | total=66498
OK   | ICS global (token correcto)        | total=180838
OK   | ICS token legacy (incorrecto)      | total=0         (el token legacy NO existe)
```

Conclusión: las etiquetas son de **servicio** (`host.services.labels.value`) y el
token ICS es **`ICS`**, no `INDUSTRIAL_CONTROL_SYSTEM`.

---

## EXPERIMENTO 4 — Conversor oficial de consultas legacy → CenQL

**Objetivo:** obtener la traducción autoritativa de las consultas del Apéndice A
del TFG, directamente desde tu cuenta.

```bash
.venv/bin/python - <<'PY'
import os
from censys_platform import SDK
sdk = SDK(personal_access_token=os.environ["CENSYS_PAT"],
          organization_id=os.environ["CENSYS_ORG_ID"])
legacy = [
    "services.port: 502 and not labels: honeypot",
    "labels: honeypot",
    "labels: industrial-control-system",
    "services.port: 102 and location.country_code: ES",
]
res = sdk.global_data.convert_legacy_search_queries(
    search_convert_query_input_body={"queries": legacy}).model_dump()
for item in res["result"]["result"]:
    print("LEGACY :", item["original_query"])
    print("  CenQL:", item.get("converted_query"))
    if item.get("errors"):
        print("  ERR  :", [e["message"] for e in item["errors"]])
    print()
PY
```

**Resultado esperado (extracto):**

```
LEGACY : services.port: 502 and not labels: honeypot
  CenQL: host.services.port:"502" and not host.services.labels.value="HONEYPOT"

LEGACY : labels: industrial-control-system
  CenQL:
  ERR  : ["no direct conversion for label 'industrial-control-system' exists"]
```

El campo de entrada es **`queries`** (una lista). Confirma las correcciones del
catálogo.

---

## EXPERIMENTO 5 — Descubrimiento del vocabulario real de etiquetas

**Objetivo:** ver qué etiquetas usa de verdad la Platform recolectando hosts reales.
Valida además el camino completo `collect` + *unwrap* de `host_v1.resource`.

```bash
.venv/bin/python - <<'PY'
import os
from collections import Counter
from ics_osint.censys_client import CensysPassiveClient
c = CensysPassiveClient(os.environ["CENSYS_ORG_ID"], os.environ["CENSYS_PAT"], page_size=50)
res = c.collect('host.services.port=502', max_records=50)
print("recuperados:", res["retrieved"], "| total índice:", res["total"])
svc = Counter()
for h in res["hosts"]:
    for s in (h.get("services") or []):
        for lab in (s.get("labels") or []):
            v = lab.get("value") if isinstance(lab, dict) else lab
            if v: svc[v] += 1
print("etiquetas de servicio:", dict(svc.most_common()))
print("claves de host[0]:", list(res["hosts"][0].keys()))   # -> ['autonomous_system','ip','location','services']
PY
```

**Resultado esperado:** un diccionario con etiquetas como
`NETWORK, VPN, LOGIN_PAGE, ICS, IOT, CAMERA, REMOTE_ACCESS, BUILDING_AUTOMATION...`
y `claves de host[0]` con la forma **plana** del host (confirma que el *unwrap*
funciona).

---

## EXPERIMENTO 6 — Demostración del bug de `fields` (software vacío)

**Objetivo:** mostrar por qué el toolkit **no** restringe `fields` por defecto:
hacerlo vacía los objetos `software` y anula la correlación CVE.

```bash
.venv/bin/python - <<'PY'
import os, json
from censys_platform import SDK
from ics_osint.censys_client import _to_plain, _extract_hits, DEFAULT_FIELDS
sdk = SDK(personal_access_token=os.environ["CENSYS_PAT"],
          organization_id=os.environ["CENSYS_ORG_ID"])
q = 'host.services.port=102 and host.location.country_code="ES"'

def first_software(fields):
    body = {"query": q, "page_size": 5}
    if fields: body["fields"] = fields
    payload = _to_plain(sdk.global_data.search(
        search_query_input_body=body, organization_id=os.environ["CENSYS_ORG_ID"]))
    for h in _extract_hits(payload):
        for s in (h.get("services") or []):
            if s.get("software"):
                return s["software"]
    return None

print("CON fields (DEFAULT_FIELDS):", json.dumps(first_software(DEFAULT_FIELDS), default=str)[:120])
print("SIN fields (completo)     :", json.dumps(first_software(None),          default=str)[:200])
PY
```

**Resultado esperado:**

```
CON fields (DEFAULT_FIELDS): [{}, {}]                              <- software VACÍO
SIN fields (completo)     : [{"confidence":..., "cpe":"cpe:2.3:...", "vendor":"...", "product":"...", ...}]
```

Por eso el cliente envía la proyección completa por defecto.

---

## EXPERIMENTO 7 — Pipeline completo F3→F7 en vivo (muestra pequeña)

**Objetivo:** ejecutar la cadena entera contra datos reales y obtener una
correlación CVE verificable, sin consumir cuota (pocos registros).

```bash
rm -rf data/raw data/clean data/cve output

.venv/bin/python cli.py collect    --config config/config.yaml \
    --queries config/queries.test.yaml --max 5
.venv/bin/python cli.py filter     --config config/config.yaml
.venv/bin/python cli.py correlate  --config config/config.yaml --kev
.venv/bin/python cli.py report     --config config/config.yaml

cat output/informe.md
cat output/hallazgos.csv
```

**Resultado esperado:** ~13 hosts depurados, varios CRÍTICOS por VNC expuesto, y al
menos una correlación real: **CVE-2023-6448** (Unitronics Vision Series, en **KEV**,
CVSS 9.8) sobre los hosts cuyo `software.vendor` es `unitronics`. IPs reales
anonimizadas (`92.95.x.x`), organizaciones omitidas.

> `config/queries.test.yaml` incluye consultas dirigidas
> (`host.services.software.vendor="siemens"`, `"unitronics"`) precisamente para que
> la correlación con el catálogo semilla tenga material que casar.

---

## EXPERIMENTO 8 — Contadores reproducibles del estudio (Apéndice A)

**Objetivo:** reproducir los contadores por consulta del catálogo completo (la base
cuantitativa del capítulo 5 del TFG), sin descargar hosts.

```bash
.venv/bin/python cli.py collect --count-only \
    --config config/config.yaml --queries config/queries.yaml
cat output/counts.csv
```

**Resultado esperado:** `output/counts.csv` con una fila por consulta del Apéndice A
(`id, region, description, total, retrieved`). Es la versión reproducible y
automatizada de las búsquedas manuales del TFG.

**Contadores de referencia (junio 2026, orden de magnitud):**

| Consulta | Total |
|---|---:|
| Modbus 502 global | ~111.000 |
| Modbus 502 global sin honeypots | ~109.000 |
| ICS España | ~7.300 |
| ICS + VNC España | ~350 |
| Modbus España sin honeypots | ~3.000 |

---

## Recolección completa (uso real del estudio)

Para reproducir el estudio entero (no solo una muestra), usa el catálogo completo
y el pipeline `all`. Ajusta `--max` según tu plan y cuota:

```bash
rm -rf data/raw data/clean data/cve output
.venv/bin/python cli.py all \
    --config config/config.yaml --queries config/queries.yaml --kev --max 200
```

Salidas en `output/`: `informe.md`, `hallazgos.csv`, `counts.csv`, `summary.json`.

---

## Limpieza

```bash
rm -rf data/raw data/clean data/cve data/counts.json data/kev_cache.json output
# Para empezar de cero del todo (incluye el venv):
# rm -rf .venv
```

> **Seguridad:** si tecleaste el PAT en el terminal, queda en el historial del shell
> y en logs. Conviene **rotar/regenerar el PAT** tras las pruebas.
