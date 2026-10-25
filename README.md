# telmex-steren-config

Scripts de auditoria y configuracion para dos routers:

- **TELMEX / Sercomm GPON** (`telmex_config.py`)
- **Steren COM-870+** (`steren_config.py`)

No incluyen contrasenas. Las credenciales se leen de variables de entorno.

## Requisitos

- Python 3.10+
- `openssl` en `PATH` (solo para Steren; se usa para AES-128-CBC)

No requiere `pip install`.

## Configuracion

```bash
cp .env.example .env
# edita .env con tus claves reales
set -a
source .env
set +a
```

Variables:

| Variable | Default | Uso |
|---|---|---|
| `TELMEX_HOST` | `10.0.0.10` | IP LAN del modem TELMEX |
| `TELMEX_USER` | `TELMEX` | Usuario admin |
| `TELMEX_PASSWORD` | — | Clave admin |
| `STEREN_HOST` | `10.10.10.10` | IP LAN del Steren |
| `STEREN_USER` | `admin` | Usuario admin |
| `STEREN_PASSWORD` | — | Clave admin |
| `STEREN_IV` | `EU5H62G9ICGRNI43` | IV AES del firmware |

## Uso rapido

```bash
# Solo lectura: guarda JSON en backups/
./telmex_config.py audit
./steren_config.py audit

# Ver un modulo concreto del Steren
./steren_config.py get wifiBasicCfg

# Dry-run: muestra que cambiaria, no escribe
./telmex_config.py apply examples/telmex.example.json
./steren_config.py apply examples/steren.example.json

# Aplicar de verdad (hace backup antes)
./telmex_config.py apply examples/telmex.example.json --yes
./steren_config.py apply examples/steren.example.json --yes
```

## Seguridad y alcance

- `apply` sin `--yes` es **dry-run**.
- `apply --yes` guarda un backup en `backups/` antes de escribir.
- Cambiar `LanIP`, SSID, canal o clave puede cortar la conexion Wi-Fi.
- El modem TELMEX puede rechazar el login con `"2"` si hay otra sesion
  administrativa abierta. El script sale con codigo `2`; no fuerza la sesion.
- El TELMEX no permite escribir WAN/PPPoE de forma fiable desde su API
  (devuelve valores de relleno). Este repo solo automatiza LAN, Wi-Fi y WPS.
- El guest Wi-Fi del Steren se conserva; si quieres desactivarlo, edita el
  perfil y aplica `wifiGuest.guestEn=false`.

## Estructura

```text
telmex_config.py       # audit/backup/login/apply TELMEX
steren_config.py       # audit/backup/get/apply Steren
examples/              # perfiles de ejemplo (sin claves)
backups/               # salida local, ignorada por git
.env.example           # plantilla de variables
```

## Perfiles de ejemplo

`examples/telmex.example.json` contiene secciones `lan`, `wifi` y `wps`.
`examples/steren.example.json` contiene modulos `lanCfg`, `wifiBasicCfg`,
`wifiAdvCfg` y `upnpCfg`.

Revisa y ajusta los valores antes de usar `--yes`. Los ejemplos usan las redes
actuales como referencia, no son una recomendacion universal.
