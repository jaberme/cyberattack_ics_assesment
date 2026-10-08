# ICS-OSINT Toolkit

[![DOI](https://zenodo.org/badge/DOI/10.5281/zenodo.23249859.svg)](https://doi.org/10.5281/zenodo.23249859)

Automatización **estrictamente pasiva** del estudio OSINT de exposición ICS/OT
del TFG *«Estudio de la exposición de infraestructuras industriales en Internet
mediante técnicas OSINT»* (Universidad de Almería, curso 2025/2026; autora:
Leilla Benkhajjou Mezgar; directores: M.ª Mercedes Peralta López y José Antonio
Álvarez Bermejo).

## Principio rector: pasividad

El toolkit **solo lee índices públicos** (Censys Platform, NVD, catálogo KEV de
CISA). No escanea, no sondea, no se conecta a VNC/RDP/HMI ni captura paneles por
conexión directa al objetivo. Esa frontera es la que separa el OSINT pasivo del
acceso no autorizado (arts. 197 bis y ss. del Código Penal; RGPD/LOPDGDD).

> **Bitácora de creación y validación:** [`CreacionCensys.md`](CreacionCensys.md)
> documenta cómo se construyó el toolkit, los bugs corregidos contra el SDK real
> (`censys-platform 0.14.3`), la sintaxis CenQL validada y los resultados de las
> pruebas offline y en vivo. Útil como referencia para futuros proyectos.
>
> **Replicación de los ensayos:** [`instruccionesReplicacion.md`](instruccionesReplicacion.md)
> recoge, experimento a experimento, los comandos exactos y los resultados esperados
> para reproducir todas las pruebas desde la línea de comandos.

## Instalación

```bash
pip install -r requirements.txt          # censys-platform, requests, PyYAML
cp config/config.example.yaml config/config.yaml

export CENSYS_ORG_ID="..."               # organización de la Platform
export CENSYS_PAT="..."                  # Personal Access Token
export NVD_API_KEY="..."                 # opcional (recomendado)
```

## Uso

```bash
# Pipeline completo (recolección -> filtrado -> correlación -> informe)
python cli.py all --config config/config.yaml --queries config/queries.yaml --kev

# Fase a fase
python cli.py collect   --config config/config.yaml --queries config/queries.yaml
python cli.py collect   --config config/config.yaml --count-only   # solo contadores
python cli.py filter    --config config/config.yaml
python cli.py correlate --config config/config.yaml --nvd --kev
python cli.py report    --config config/config.yaml
```

Salidas en `output/`: `informe.md` (tablas del capítulo 5), `hallazgos.csv` (IPs
anonimizadas), `counts.csv` (Apéndice A reproducible) y `summary.json`.

## Mapeo a las fases de la metodología (TFG)

| Fase | Actividad | Módulo |
|---|---|---|
| F1 | Definición del alcance | `config/queries.yaml`, `config.yaml` |
| F2 | Diseño de consultas Censys | `censys_client` + `queries.yaml` |
| F3 | Recolección de datos | `censys_client` (`count` / `collect`) |
| F4 | Filtrado y depuración | `filters` |
| F5a | Extracción de *fingerprint* | `fingerprint` |
| F5b | Correlación con NVD / KEV | `nvd_client` + `cve_correlation` |
| F5c | Clasificación de severidad | `severity` (Tabla 4.3) |
| F6 | Contextualización / agregación | `aggregate` |
| F7 | Anonimización y documentación | `anonymize` + `report` |

Las fases sin red (F4–F7) se ejecutan de forma independiente y reproducible
sobre los artefactos JSON intermedios.

## Validación offline

El pipeline F4–F7 se valida contra un *fixture* sintético con IPs de
documentación (RFC 5737), sin tocar ningún sistema real:

```bash
mkdir -p data/raw && cp samples/raw_sample.json data/raw/muestra.json
python cli.py filter    --config config/config.yaml
python cli.py correlate --config config/config.yaml --kev
python cli.py report    --config config/config.yaml
```

Resultado esperado: 5 hosts depurados (2 falsos positivos excluidos: un honeypot
y una instancia cloud sin etiqueta ICS), 5 hallazgos correlacionados (3 CRÍTICOS).

## Disclaimer

- No escanea ni sondea los sistemas identificados (solo lee el índice de Censys).
- No se conecta a VNC/RDP/HMI ni captura pantallas conectándose al objetivo.
- No explota vulnerabilidades: la correlación es *potencial*, basada en el
  *fingerprint* indexado.
- No publica IPs completas, credenciales ni nombres de organización: la
  anonimización se aplica por defecto en todas las salidas.
