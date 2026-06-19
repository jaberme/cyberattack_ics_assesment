"""ICS-OSINT Toolkit — automatización de OSINT *pasivo* para exposición ICS/OT.

Acompaña al Trabajo Fin de Grado «Estudio de la exposición de infraestructuras
industriales en Internet mediante técnicas OSINT» (Universidad de Almería,
curso 2025/2026).

PRINCIPIO RECTOR — PASIVIDAD
============================
Toda la recolección es estrictamente PASIVA. El toolkit consulta el índice
público de Censys (Platform API) y bases de datos de vulnerabilidades
(NVD y catálogo KEV de CISA). En ningún momento se conecta, escanea, sondea
ni interactúa con los sistemas identificados. No se incluye —de forma
deliberada— ninguna funcionalidad de escaneo activo de protocolos industriales
(Modbus, S7Comm, etc.), conexión a VNC/RDP, ni captura de paneles HMI mediante
conexión directa al objetivo. Hacerlo cruzaría la frontera de lo pasivo y
podría constituir acceso no autorizado a sistemas de información
(arts. 197 bis y ss. del Código Penal español).

Las siete fases de la metodología del TFG se mapean a los módulos así:

    F1  Definición del alcance ............ config/queries.yaml
    F2  Diseño de consultas Censys ........ censys_client + queries.yaml
    F3  Recolección de datos .............. censys_client (count/collect)
    F4  Filtrado y depuración ............. filters
    F5  Análisis de vulnerabilidades ...... fingerprint + nvd_client +
                                            cve_correlation + severity
    F6  Contextualización geopolítica ..... aggregate (mapa región-sector)
    F7  Documentación y anonimización ..... anonymize + report
"""

__version__ = "1.0.0"
__all__ = [
    "config",
    "censys_client",
    "filters",
    "fingerprint",
    "nvd_client",
    "cve_correlation",
    "severity",
    "anonymize",
    "aggregate",
    "report",
]
