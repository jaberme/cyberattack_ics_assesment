"""Fase 5c — Clasificación de severidad de hallazgos (Tabla 4.3 del TFG).

Combina la puntuación CVSS, el tipo de exposición observable (acceso remoto sin
autenticación, credenciales por defecto) y la presencia en el catálogo KEV de
CISA para asignar uno de cuatro niveles: CRÍTICO, ALTO, MEDIO, BAJO.

La pertenencia al catálogo KEV eleva automáticamente la severidad, conforme al
criterio descrito en la Sección 4.4.1.
"""

from __future__ import annotations

from dataclasses import dataclass

CRITICO = "CRÍTICO"
ALTO = "ALTO"
MEDIO = "MEDIO"
BAJO = "BAJO"

ORDER = {BAJO: 0, MEDIO: 1, ALTO: 2, CRITICO: 3}

# Protocolos inseguros por diseño (sin autenticación/cifrado nativos), Tabla 2.2.
INSECURE_PROTOCOL_PORTS = {502, 2404, 20000, 47808, 20256}
# Servicios de acceso remoto cuya exposición sin autenticación es crítica.
REMOTE_ACCESS_PORTS = {5900, 3389, 23}


@dataclass
class SeverityInputs:
    """Señales observables para clasificar un hallazgo."""

    max_cvss: float | None = None
    in_kev: bool = False
    exposed_remote_access: bool = False      # VNC/RDP/Telnet accesible
    default_credentials: bool = False        # credenciales por defecto documentadas
    insecure_protocol_only: bool = False     # p. ej. Modbus sin CVE activa
    info_disclosure: bool = False            # banner revela modelo/versión


def classify(inp: SeverityInputs) -> str:
    """Devuelve el nivel de severidad según los criterios de la Tabla 4.3."""
    cvss = inp.max_cvss or 0.0

    # CRÍTICO: CVSS >= 9.0, o credenciales por defecto, o KEV, o acceso remoto
    # visual sin autenticación (VNC/HMI expuesto).
    if cvss >= 9.0 or inp.default_credentials or inp.in_kev:
        return CRITICO
    if inp.exposed_remote_access and not inp.default_credentials:
        # VNC/RDP/Telnet expuesto: acceso directo al proceso/host -> CRÍTICO.
        return CRITICO

    # ALTO: CVSS 7.0–8.9 o autenticación observable débil.
    if 7.0 <= cvss < 9.0:
        return ALTO

    # MEDIO: exposición de información sensible o protocolo inseguro sin CVE.
    if inp.info_disclosure or inp.insecure_protocol_only:
        return MEDIO

    # BAJO: puerto abierto sin servicio identificado o versión sin CVE pública.
    return BAJO


def max_level(levels: list[str]) -> str:
    """Devuelve el nivel más severo de una lista."""
    if not levels:
        return BAJO
    return max(levels, key=lambda lv: ORDER.get(lv, 0))
