#!/usr/bin/env python3
"""
Configuracion segura del modem TELMEX (Sercomm GPON).

Uso:
  export TELMEX_HOST=10.0.0.10
  export TELMEX_USER=TELMEX
  export TELMEX_PASSWORD='...'
  ./telmex_config.py audit
  ./telmex_config.py apply examples/telmex.example.json --yes

Reglas:
  - `audit` y `apply` sin --yes son de solo lectura.
  - `apply` hace un backup antes de escribir.
  - No se escriben passwords en el repo ni en los logs.
  - El firmware puede bloquear el login mientras otro usuario tiene el panel
    abierto. En ese caso el script sale con codigo 2 y no fuerza la sesion.
"""

from __future__ import annotations

import argparse
import hashlib
import hmac
import http.client
import json
import os
import re
import sys
import time
import urllib.parse
from datetime import datetime
from pathlib import Path
from typing import Any

DEFAULT_HOST = "10.0.0.10"
DEFAULT_USER = "TELMEX"

WIFI_KEYS = [
    "mesh_enable",
    "band_steering_enable",
    "wifi_network_onoff",
    "wifi_ssid",
    "wifi_channel",
    "wifi_obss",
    "wifi_broadcast_ssid",
    "wireless_multicast",
    "block_wireless_bridging",
    "wifi_protection",
    "encryption_technique",
    "wifi_password",
    "wifi_number_of_wifi_devices",
    "wifi_network_onoff_5g",
    "wifi_ssid_5g",
    "wifi_channel_5g",
    "wifi_obss_5g",
    "wifi_broadcast_ssid_5g",
    "wireless_multicast_5g",
    "block_wireless_bridging_5g",
    "wifi_protection_5g",
    "encryption_technique_5g",
    "wifi_password_5g",
    "wifi_number_of_wifi_devices_5g",
]

AUDIT_ENDPOINTS = {
    "status": "data/statussupportstatus.json",
    "overview": "data/overview.json",
    "wifi_general": "data/wifi_general.json",
    "wifi_wps": "data/wifi_wps.json",
    "wifi_mac_filter": "data/wifi_mac_filter.json",
    "settings_lan": "data/settings_lan.json",
    "settings_lan_staticdhcp": "data/settings_lan_staticdhcp.json",
    "settings_lan_device": "data/settings_lan_device.json",
    "settings_access_control": "data/settings_access_control.json",
    "settings_tr069": "data/settings_tr069.json",
    "settings_snmp": "data/settings_snmp.json",
    "internet_firewall": "data/internet_firewall.json",
    "internet_upnp": "data/internet_upnp.json",
    "internet_port_mapping": "data/internet_port_mappin.json",
    "user_data": "data/user_data.json",
}

READ_ONLY_KEYS = {"wifi_now_channel", "wifi_now_bandwidth", "wifi_now_channel_5g", "wifi_now_bandwidth_5g"}
SECRET_KEYS = {"wifi_password", "wifi_password_5g", "wanPPPoEPwd", "wanPppoePwd", "LanDNSServer"}


class TelmexError(RuntimeError):
    pass


class TelmexAuthError(TelmexError):
    pass


class TelmexSessionBusy(TelmexError):
    pass


def _now() -> str:
    return datetime.now().strftime("%Y%m%d-%H%M%S")


def _flatten(value: Any) -> dict[str, Any]:
    """Convierte [{a:1},{b:2}] en {a:1,b:2}."""
    out: dict[str, Any] = {}
    if isinstance(value, dict):
        out.update(value)
    elif isinstance(value, list):
        for item in value:
            if isinstance(item, dict):
                out.update(item)
    return out


def _safe(value: Any) -> Any:
    if isinstance(value, str) and len(value) > 80:
        return value[:77] + "..."
    return value


class TelmexClient:
    def __init__(self, host: str, user: str, password: str, timeout: float = 15.0):
        self.host = host
        self.user = user
        self.password = password
        self.timeout = timeout
        self.sid: str | None = None
        self.csrf: str | None = None

    def _request(
        self,
        method: str,
        path: str,
        *,
        headers: dict[str, str] | None = None,
        body: bytes | None = None,
        timeout: float | None = None,
    ) -> tuple[int, dict[str, str], bytes]:
        h = {
            "User-Agent": "telmex-config/1.0",
            "Accept": "application/json, text/javascript, */*; q=0.01",
            "Accept-Language": "es-MX,es;q=0.9",
            "X-Requested-With": "XMLHttpRequest",
            "Connection": "close",
        }
        if headers:
            h.update(headers)
        conn = http.client.HTTPConnection(self.host, 80, timeout=timeout or self.timeout)
        try:
            conn.request(method, path, body=body, headers=h)
            resp = conn.getresponse()
            data = resp.read()
            hdrs = {k.lower(): v for k, v in resp.getheaders()}
            return resp.status, hdrs, data
        except (OSError, http.client.HTTPException) as exc:
            raise TelmexError(f"No se pudo conectar a {self.host}: {exc}") from exc
        finally:
            conn.close()

    def _get(self, path: str, *, accept: str = "application/json, text/javascript, */*; q=0.01") -> bytes:
        _, _, data = self._request(
            "GET",
            path,
            headers={
                "Accept": accept,
                "Referer": f"http://{self.host}/status-and-support.html",
            },
        )
        return data

    def login(self) -> None:
        html = self._request(
            "GET",
            "/login.html",
            headers={"Accept": "text/html,*/*", "Referer": f"http://{self.host}/login.html"},
        )[2]
        m = re.search(rb"csrf_token = '([^']+)'", html)
        if not m:
            raise TelmexAuthError("No se encontro csrf_token en /login.html")
        self.csrf = m.group(1).decode()

        raw_lang = self._get("/data/user_lang.json")
        try:
            lang = json.loads(raw_lang)
        except json.JSONDecodeError as exc:
            raise TelmexAuthError("user_lang.json no es JSON") from exc
        keys = [x["encryption_key"] for x in lang if isinstance(x, dict) and "encryption_key" in x]
        if not keys:
            raise TelmexAuthError("No se encontro encryption_key")
        key = keys[0]
        h1 = hmac.new(b"$1$SERCOMM$", self.password.encode(), hashlib.sha256).hexdigest()
        hp = hmac.new(key.encode(), h1.encode(), hashlib.sha256).hexdigest()
        body = urllib.parse.urlencode({"LoginName": self.user, "LoginPWD": hp}).encode()
        st, hdrs, data = self._request(
            "POST",
            f"/data/login.json?_={int(time.time() * 1000)}&csrf_token={urllib.parse.quote(self.csrf)}",
            headers={
                "Content-Type": "application/x-www-form-urlencoded; charset=UTF-8",
                "Referer": f"http://{self.host}/login.html",
            },
            body=body,
        )
        code = data.decode("utf-8", "replace").strip()
        if code.startswith('"1"'):
            cookie = hdrs.get("set-cookie", "")
            m = re.search(r"session_id=([^;]+)", cookie)
            if not m:
                raise TelmexAuthError("Login aceptado, pero sin session_id")
            self.sid = m.group(1)
            return
        if code.startswith('"2"'):
            raise TelmexSessionBusy(
                "El modem reporta una sesion administrativa abierta. "
                "Cierra el panel TELMEX (o espera a que expire) y vuelve a intentar."
            )
        if code.startswith(('"3"', '"5"')):
            raise TelmexAuthError("Contrasena de administrador incorrecta.")
        if code.startswith('"4"'):
            raise TelmexAuthError("Usuario de administrador incorrecto.")
        raise TelmexAuthError(f"Login rechazado por el modem: {code[:80]!r}")

    def _cookie_headers(self) -> dict[str, str]:
        if not self.sid:
            self.login()
        return {
            "Cookie": f"session_id={self.sid}",
            "Referer": f"http://{self.host}/status-and-support.html",
        }

    def get_json(self, path: str, *, retry_login: bool = True) -> Any:
        for attempt in range(2):
            st, _, data = self._request("GET", path, headers=self._cookie_headers())
            if st != 200:
                raise TelmexError(f"{path}: HTTP {st}")
            if b"login.html" in data[:500]:
                if retry_login and attempt == 0:
                    self.login()
                    continue
                raise TelmexError(f"{path}: sesion expirada")
            try:
                return json.loads(data)
            except json.JSONDecodeError as exc:
                raise TelmexError(f"{path}: respuesta no JSON") from exc
        raise TelmexError(f"{path}: no se pudo leer")

    def post_form(self, path: str, fields: dict[str, Any], *, retry_login: bool = True) -> bytes:
        body = urllib.parse.urlencode({k: "" if v is None else v for k, v in fields.items()}).encode()
        for attempt in range(2):
            st, _, data = self._request(
                "POST",
                path,
                headers={
                    **self._cookie_headers(),
                    "Content-Type": "application/x-www-form-urlencoded; charset=UTF-8",
                },
                body=body,
            )
            if st != 200:
                raise TelmexError(f"{path}: HTTP {st}")
            if b"login.html" in data[:500] and retry_login and attempt == 0:
                self.login()
                continue
            return data
        raise TelmexError(f"{path}: no se pudo escribir")


def _write_json(outdir: Path, name: str, value: Any) -> None:
    outdir.mkdir(parents=True, exist_ok=True)
    (outdir / f"{name}.json").write_text(
        json.dumps(value, ensure_ascii=False, indent=2), encoding="utf-8"
    )


def audit(client: TelmexClient, outdir: Path) -> dict[str, Any]:
    results: dict[str, Any] = {}
    for name, path in AUDIT_ENDPOINTS.items():
        try:
            value = client.get_json(path)
            results[name] = value
            _write_json(outdir, name, value)
            print(f"  OK  {name:28} {path}")
        except TelmexError as exc:
            print(f"  --  {name:28} {path} ({exc})")
    wan = _flatten(results.get("status"))
    lan = results.get("settings_lan")
    wifi = _flatten(results.get("wifi_general"))
    print("\nResumen TELMEX")
    for key in ("connectStatus", "wanIP", "wanGateway", "wanDns1", "wanDns2"):
        if key in wan:
            print(f"  WAN {key}: {_safe(wan[key])}")
    if isinstance(lan, list):
        select = next((x.get("select_lan_network") for x in lan if isinstance(x, dict) and "select_lan_network" in x), None)
        subnets = [x for x in lan if isinstance(x, dict) and "subnet" in x]
        if subnets:
            s = subnets[0]
            print(f"  LAN: {s.get('LanIP')}/{s.get('LanSubnetMask')} DHCP={s.get('LanDHCP')} "
                  f"{s.get('LanDHCPStartIP')}-{s.get('LanDHCPEndIP')} DNS={s.get('LanDNSServer')}")
        if select is not None:
            print(f"  LAN select: {select}")
    if wifi:
        print(f"  WiFi 2.4: SSID={_safe(wifi.get('wifi_ssid'))} ch={wifi.get('wifi_channel')} "
              f"mode={wifi.get('wifi_protection')}")
        print(f"  WiFi 5G : SSID={_safe(wifi.get('wifi_ssid_5g'))} ch={wifi.get('wifi_channel_5g')} "
              f"mode={wifi.get('wifi_protection_5g')}")
    print(f"\nBackup/auditoria: {outdir}")
    return results


def _apply_wifi(client: TelmexClient, patch: dict[str, Any]) -> None:
    if not isinstance(patch, dict):
        raise TelmexError("La seccion 'wifi' debe ser un objeto")
    current = client.get_json("data/wifi_general.json")
    cur = _flatten(current)
    if not cur:
        raise TelmexError("No se pudo leer wifi_general.json")
    merged = {**cur, **patch}
    changed = sorted(k for k in patch if k not in READ_ONLY_KEYS)
    if any(k in SECRET_KEYS for k in changed):
        print("  AVISO: el perfil cambia una clave o DNS; se aplicara tal cual.")
    fields = {k: merged.get(k, "") for k in list(WIFI_KEYS) + list(patch) if k in merged}
    print(f"  WiFi: aplicando {', '.join(changed) or '(sin cambios)'}")
    client.post_form("data/wifi_general.json", fields)
    print("  WiFi: enviado")


def _apply_lan(client: TelmexClient, patch: dict[str, Any]) -> None:
    if not isinstance(patch, dict):
        raise TelmexError("La seccion 'lan' debe ser un objeto")
    data = client.get_json("data/settings_lan.json")
    if not isinstance(data, list):
        raise TelmexError("settings_lan.json no tiene el formato esperado")
    select = next((x.get("select_lan_network") for x in data if isinstance(x, dict) and "select_lan_network" in x), None)
    subnets = [dict(x) for x in data if isinstance(x, dict) and "subnet" in x]
    if not subnets:
        raise TelmexError("No se encontro la subred LAN")
    before = {k: subnets[0].get(k) for k in patch}
    subnets[0].update(patch)
    changed = sorted(k for k in patch if before.get(k) != subnets[0].get(k))
    print(f"  LAN: aplicando {', '.join(changed) or '(sin cambios)'}")
    fields = {
        "settingsLanSelectLanNetwork": select if select is not None else "0",
        "settingsLanSubnet": json.dumps(subnets, ensure_ascii=False, separators=(",", ":")),
    }
    client.post_form("data/settings_lan.json", fields)
    print("  LAN: enviado. Si cambiaste LanIP, la conexion puede cortarse.")


def _apply_wps(client: TelmexClient, patch: dict[str, Any]) -> None:
    fields = {"wps_24g_onoff": "0", "wps_5g_onoff": "0", "wps20_enable": "0"}
    if isinstance(patch, dict):
        fields.update({k: v for k, v in patch.items()})
    print(f"  WPS: {fields}")
    client.post_form("data/wifi_wps.json", fields)
    print("  WPS: enviado")


def apply_profile(client: TelmexClient, profile: dict[str, Any], outdir: Path, yes: bool) -> None:
    allowed = {"lan", "wifi", "wps"}
    unknown = set(profile) - allowed
    if unknown:
        raise TelmexError(f"Secciones no soportadas: {', '.join(sorted(unknown))}")
    if not yes:
        print("DRY-RUN. Esto es lo que se aplicaria:")
        print(json.dumps(profile, ensure_ascii=False, indent=2))
        print("\nAgrega --yes para escribir en el modem.")
        return

    print("Backup previo...")
    backup = audit(client, outdir)
    required = {
        "wps": "wifi_wps",
        "wifi": "wifi_general",
        "lan": "settings_lan",
    }
    for section, key in required.items():
        if section in profile and key not in backup:
            raise TelmexError(
                f"Backup incompleto: no se pudo leer {key}; no se aplica '{section}'."
            )
    if "wps" in profile:
        _apply_wps(client, profile["wps"])
    if "wifi" in profile:
        _apply_wifi(client, profile["wifi"])
    if "lan" in profile:
        _apply_lan(client, profile["lan"])
    print("Aplicacion terminada.")


def _client_from_env() -> TelmexClient:
    host = os.environ.get("TELMEX_HOST", DEFAULT_HOST)
    user = os.environ.get("TELMEX_USER", DEFAULT_USER)
    password = os.environ.get("TELMEX_PASSWORD")
    if not password:
        raise SystemExit("Falta TELMEX_PASSWORD en el entorno.")
    return TelmexClient(host, user, password)


def main() -> int:
    parser = argparse.ArgumentParser(description="Auditoria y configuracion del modem TELMEX/Sercomm")
    sub = parser.add_subparsers(dest="cmd", required=True)
    for name in ("audit", "backup"):
        p = sub.add_parser(name, help="Lee configuracion y guarda JSON")
        p.add_argument("--out", default=f"backups/telmex-{name}-{_now()}")
    p = sub.add_parser("apply", help="Aplica un perfil JSON")
    p.add_argument("profile")
    p.add_argument("--out", default=f"backups/telmex-apply-{_now()}")
    p.add_argument("--yes", action="store_true", help="Escribe cambios (sin esto es dry-run)")
    p = sub.add_parser("login", help="Solo comprueba el login")
    args = parser.parse_args()

    try:
        client = _client_from_env()
        if args.cmd in ("audit", "backup"):
            client.login()
            audit(client, Path(args.out))
        elif args.cmd == "login":
            client.login()
            print("Login OK")
        elif args.cmd == "apply":
            client.login()
            profile = json.loads(Path(args.profile).read_text(encoding="utf-8"))
            apply_profile(client, profile, Path(args.out), args.yes)
        return 0
    except TelmexSessionBusy as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 2
    except (TelmexAuthError, TelmexError, OSError, json.JSONDecodeError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
