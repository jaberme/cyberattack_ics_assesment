# Bitácora de creación y validación del ICS-OSINT Toolkit
Entorno: Linux, Python 3.12, `censys-platform 0.14.3`.

---

## 1. Objetivo de la sesión

1. **Materializar** el toolkit en una estructura de ficheros ejecutable.
2. **Probar la fase F3** (recolección en vivo contra el índice real de Censys).

El principio rector es la **pasividad estricta**: el toolkit solo lee índices
públicos (Censys Platform, NVD, KEV de CISA). No escanea, no sondea, no se conecta
a VNC/RDP/HMI. Esa frontera es la que separa el OSINT pasivo del acceso no
autorizado (arts. 197 bis CP; RGPD/LOPDGDD).

---

## 2. Estructura final del toolkit

Ruta: `/ics-osint-toolkit/`

```
ics-osint-toolkit/
├── cli.py                      # subcomandos: collect / filter / correlate / report / all
├── requirements.txt            # censys-platform>=0.13, requests>=2.31, PyYAML>=6.0
├── README.md
├── .gitignore                  # excluye config.yaml, data/raw|clean|cve, output/, .venv/
├── config/
│   ├── config.example.yaml     # secretos por ${env:VAR}; regiones; filtros; anonimización
│   ├── config.yaml             # copia local (sin secretos: resuelve env en runtime)
│   ├── queries.yaml            # catálogo Apéndice A en CenQL (corregido, ver §5)
│   └── queries.test.yaml       # consultas mínimas para validar conectividad F3
├── data/
│   └── cve_seed.yaml           # catálogo semilla CVEs ICS (Tabla 2.4 del TFG)
├── samples/
│   └── raw_sample.json         # prueba sintética (IPs RFC 5737) para pruebas offline
└── ics_osint/
    ├── __init__.py             ├── nvd_client.py
    ├── config.py               ├── cve_correlation.py
    ├── censys_client.py        ├── severity.py
    ├── filters.py              ├── anonymize.py
    ├── fingerprint.py          └── aggregate.py
    └── report.py
```

Mapeo a las 7 fases de la metodología:

| Fase | Actividad | Módulo |
|---|---|---|
| F1 | Definición del alcance | `config/queries.yaml`, `config.yaml` |
| F2 | Diseño de consultas Censys | `censys_client` + `queries.yaml` |
| F3 | Recolección de datos | `censys_client` (`count` / `collect`) |
| F4 | Filtrado y depuración | `filters` |
| F5a | Extracción de *fingerprint* | `fingerprint` |
| F5b | Correlación NVD / KEV | `nvd_client` + `cve_correlation` |
| F5c | Clasificación de severidad | `severity` (Tabla 4.3) |
| F6 | Contextualización / agregación | `aggregate` |
| F7 | Anonimización y documentación | `anonymize` + `report` |

Las fases sin red (F4–F7) son independientes y reproducibles sobre artefactos JSON
intermedios.

---

## 3. Instalación y entorno 

Debian/Ubuntu marca el entorno como *externally managed* (PEP 668); **usar venv**:

```bash
cd ics-osint-toolkit
python3 -m venv .venv
.venv/bin/pip install --upgrade pip
.venv/bin/pip install -r requirements.txt     # instala censys-platform 0.14.3
cp config/config.example.yaml config/config.yaml
```

Credenciales (Censys Platform; el **PAT es secreto**):

```bash
export CENSYS_ORG_ID="....."   # formato UUID, NO el email
export CENSYS_PAT="censys_X......"             # Personal Access Token (lo tengo en la web de censys)
export NVD_API_KEY="..."                           # opcional
```

> **Lección sobre el org_id:** el `organization_id` es un **UUID**
> (p. ej. `0af95a0c-…`), que se obtiene en la consola de la Platform
> (Getting Started Step 3). Usar el email como org_id da
> `AuthenticationError: Access credentials are invalid`. Que es donde he estado atrancada un buen tiempo.

Ejecución (la recolección F3 necesita credenciales; el resto no necesita red):

```bash
.venv/bin/python cli.py collect   --config config/config.yaml --queries config/queries.yaml --max 5
.venv/bin/python cli.py filter     --config config/config.yaml
.venv/bin/python cli.py correlate  --config config/config.yaml --kev      # --nvd para NVD en vivo
.venv/bin/python cli.py report     --config config/config.yaml
# o todo de una vez:
.venv/bin/python cli.py all        --config config/config.yaml --queries config/queries.yaml --kev
```

---

## 4. ⚠️ Lo más importante: el módulo de conexión con censys NO funcionaba contra el SDK real

Contra `censys-platform 0.14.3` **fallaba**. Estos son los hallazgos de
ingeniería inversa del SDK y las correcciones aplicadas en `ics_osint/censys_client.py`.

### 4.1. Forma real de la API (SDK 0.14.3)

- **Recurso y método:** `sdk.global_data.search(search_query_input_body=..., organization_id=...)`.
- **Input body** (`SearchQueryInputBody`): campos `query`, `fields`, `page_size`,
  **`page_token`** (¡no `cursor`!).
- **Respuesta** (`V3GlobaldataSearchQueryResponse`):
  ```
  payload
    └─ result (ResponseEnvelopeSearchQueryResponse)
         └─ result (SearchQueryResponse)
              ├─ hits            -> [ SearchQueryHit, ... ]
              ├─ total_hits      -> float   (¡no int!)
              └─ next_page_token -> str
  ```
- **Cada hit** envuelve el host en `host_v1.resource` (modelo `Host`). El `Host`
  plano tiene: `ip`, `location.{country_code,country,city,province}`,
  `autonomous_system.{name,asn}` (modelo `Routing`), `labels` (lista de `Label`
  con `.value`), `services` (lista de `Service`).
- **`Service`** real: `port`, `protocol`, `banner`, `labels` (lista `Label`),
  `software`. **No tiene `service_name` ni `extended_service_name`** (el código
  los usaba como *fallback*; al no existir, cae al mapa puerto→protocolo, que es
  comportamiento aceptable).
- **`software`** es lista de objetos con `cpe`, `vendor`, `product`, `version`,
  `part`, `confidence`, `evidence`, `source`. El CPE también puede venir como
  `uniform_resource_identifier`.

### 4.2. Correcciones en `censys_client.py`

| # | Problema | Corrección |
|---|---|---|
| 1 | Hits buscados en `result.hits` | Añadido path `result.result.hits` (primero) |
| 2 | Total en `result.total` y solo `int` | Añadido `result.result.total_hits`; acepta `float`→`int()` |
| 3 | Cursor en `result.next` | Añadido `result.result.next_page_token` |
| 4 | Host plano asumido | Nuevo `_unwrap_host()`: extrae `hit.host_v1.resource`; si ya es plano (sample), lo devuelve igual |
| 5 | Paginación con `body["cursor"]` | Cambiado a `body["page_token"]` |
| 6 | `organization_id` solo en constructor | Se pasa también a `search(organization_id=self.org_id)` |
| 7 | **`fields` vaciaba `software`** | Ver §4.3 |

### 4.3. El bug crítico: `fields` rompía el fingerprinting

Síntoma: al pedir `fields=["host.ip", …, "host.services.software"]`, la Platform
devolvía `software: [{}, {}]` (objetos **vacíos**) → 0 fingerprints con
vendor/product → **0 correlaciones CVE**. Sin restricción de `fields`, el mismo
host devolvía el `software` **completo** (cpe/vendor/product/version).

Corrección: el cliente **por defecto NO envía `fields`** (proyección completa).
`DEFAULT_FIELDS` se conserva solo como referencia, con aviso. El parámetro
`fields=None` del constructor permite restringir voluntariamente, pero no se
recomienda si se quiere correlación CVE.

> **Regla general para la Censys Platform:** si necesitas los sub-campos de
> `software` (o de cualquier objeto anidado) para análisis, **no uses una
> proyección `fields` que liste solo el objeto padre**; o pides el host completo,
> o enumeras explícitamente los sub-campos.

---

## 5. Sintaxis CenQL validada contra la cuenta real

Validado con el **conversor de
consultas legacy** del SDK
(`sdk.global_data.convert_legacy_search_queries(search_convert_query_input_body={"queries":[...]})`,
campo de entrada **`queries`**, una lista) y con consultas de contador:

| Construcción | Lo que asumía `censys.md` | CenQL real validada |
|---|---|---|
| Honeypot | `not host.labels=HONEYPOT` | `not host.services.labels.value="HONEYPOT"` (etiqueta a nivel de **servicio**) |
| ICS | `host.labels=INDUSTRIAL_CONTROL_SYSTEM` | `host.services.labels.value="ICS"` (el token `INDUSTRIAL_CONTROL_SYSTEM` **no existe**) |
| Puerto | `host.services.port=502` | `host.services.port=502` ✓ (también `:"502"`) |
| País | `host.location.country_code=ES` | ✓ |
| Set de países | `host.location.country_code: {"DE","FR"}` | ✓ (también `={DE, FR}`) |
| Negación de ASN | `not host.autonomous_system.name: {"Amazon","Google"}` | ✓ |
| Banner | `host.services: (banner: "ENCO")` | ✓ (también `host.services.banner: "ENCO"`) |

**Etiquetas reales observadas** (todas a nivel de servicio, `host.services.labels.value`):
`NETWORK`, `VPN`, `LOGIN_PAGE`, **`ICS`**, `IOT`, `AI`, `CAMERA`, `WEB_SERVER`,
`REMOTE_ACCESS`, `CMS`, `ROUTER`, `FIREWALL`, `BUILDING_AUTOMATION`, `DATABASE`,
`MEDICAL`, `NVR`, `HONEYPOT`, …

Las dos correcciones de etiqueta se aplicaron con `replace_all` en `queries.yaml`;
el resto del catálogo era válido tal cual.

---

## 6. Resultados de la validación

### 6.1. Offline (F4–F7) contra el sample sintético `samples/raw_sample.json`

5 hosts depurados (2 falsos positivos: 1 honeypot + 1 cloud sin ICS), 5 hallazgos,
3 CRÍTICOS. Salida **idéntica** al informe de referencia que hice manualmente para el TFG (salvo
timestamp). Confirma severidad Tabla 4.3 (VNC es CRÍTICO; Unitronics/Rockwell→CRÍTICO
por credenciales por defecto / KEV).

### 6.2. En vivo (F3→F7) contra el índice real de Censys

Contadores reales obtenidos (coherentes con el TFG, junio 2026):

| Consulta | Total |
|---|---:|
| Modbus 502 global | 111.148 |
| Modbus 502 sin honeypots | 109.387 (66.498 honeypots globales) |
| ICS España | 7.266 |
| ICS + VNC España | 352  (TFG Fig.: 506) |
| Modbus España sin honeypots | 2.960 (TFG Fig. 5.1: 2.514) |

Pipeline completo con muestra pequeña (`--max 5`, varias consultas): 13 hosts
depurados, **correlación CVE real**: `CVE-2023-6448` (Unitronics Vision Series,
en **KEV**, CVSS 9.8) casó sobre 3 hosts reales (FR, BE, BE), bien marcados
CRÍTICO. IPs reales **anonimizadas** (`92.95.x.x`) y organizaciones omitidas en
todas las salidas.

---

## 7. Cómo se manejaron las credenciales (privacidad)

- El PAT es secreto. Se ofreció al usuario ejecutarlo él mismo con el prefijo `!`
  para que el token no pasara por el asistente; finalmente el usuario pidió que lo
  hiciera el asistente con las credenciales ya visibles.
- El toolkit **nunca almacena** el PAT: `config.yaml` usa `${env:CENSYS_PAT}` y se
  resuelve desde el entorno en runtime.
- **Aviso de seguridad reutilizable:** cualquier credencial tecleada en un terminal
  con `!` o pegada en el chat **queda en el transcript**; conviene **rotar/regenerar
  el PAT** tras la prueba.

---

## 8. Checklist reutilizable para integrar la Censys Platform en otro proyecto

1. `python3 -m venv .venv && .venv/bin/pip install "censys-platform>=0.13"`.
2. Credenciales: `organization_id` (**UUID**, no email) + PAT (`censys_…`).
3. Llamada: `SDK(personal_access_token=…, organization_id=…).global_data.search(
   search_query_input_body={"query":…, "page_size":N}, organization_id=…)`.
   **No** pasar `fields` si quieres `software` poblado.
4. Parsear respuesta: `result.result.{hits, total_hits(float), next_page_token}`;
   desenvolver cada hit con `host_v1.resource`.
5. Paginar con `page_token` en el input body.
6. Validar la sintaxis de etiquetas con `convert_legacy_search_queries`
   (entrada `{"queries":[...]}`): son de **servicio** (`host.services.labels.value`)
   y el token ICS es **`ICS`**.
7. Para correlación CVE offline: catálogo semilla por `match_keywords` (AND sobre
   vendor/product/version/protocol en minúsculas) + KEV de CISA (degradación
   elegante sin red).
8. Anonimizar SIEMPRE las salidas (truncado de IP / hash con sal; omitir org/ASN).

---

## 9. Pendientes / mejoras detectadas (no bloqueantes)

- **NVD en vivo (`--nvd`)** no se ejerció contra la API real; solo correlación con
  catálogo semilla + KEV. Pendiente de validar `search_by_cpe` / `search_by_keyword`.
- **Mapa de regiones** en `config.yaml` no cubre todos los países (p. ej. `AT`
  cayó en "Otras"); ampliar si se añaden regiones.
- **`dominant_protocol`** muestra "puerto 80/8001" cuando el host ICS expone además
  web; cosmético (se podría priorizar puertos ICS sobre web).
- Faltan tests unitarios; la validación es funcional (offline + en vivo). Cubrir la
  forma anidada `host_v1.resource`, dedup por IP, e IPv6 sería lo prioritario.
```
