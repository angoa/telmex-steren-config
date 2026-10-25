#!/usr/bin/env python3
"""
Configuracion del router Steren COM-870+ (API AES).

Uso:
  export STEREN_HOST=10.10.10.10
  export STEREN_USER=admin
  export STEREN_PASSWORD='...'
  ./steren_config.py audit
  ./steren_config.py apply examples/steren.example.json --yes

Reglas:
  - `audit` y `apply` sin --yes son de solo lectura.
  - `apply` hace un backup antes de escribir.
  - No se escriben passwords en el repo ni en los logs.
  - Requiere el binario `openssl` (AES-128-CBC).
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
import shutil
import subprocess
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime
from http.cookiejar import CookieJar
from pathlib import Path
from typing import Any

DEFAULT_HOST = "10.10.10.10"
DEFAULT_USER = "admin"
DEFAULT_IV = "EU5H62G9ICGRNI43"

AUDIT_MODULES = [
    "wanStatus",
    "wanCfg",
    "wanAdvCfg",
    "lanCfg",
    "wifiBasicCfg",
    "wifiAdvCfg",
    "wifiGuest",
    "deviceList",
    "upnpCfg",
    "ipv6Cfg",
]

READ_ONLY_MODULES = {"wanStatus", "deviceList"}
SECRET_KEYS = {
    "wifiPwd",
    "wifiPwd_5g",
    "guestPwd",
    "wanPPPoEPwd",
    "guestPwd5g",
}


class SterenError(RuntimeError):
    pass


class SterenAuthError(SterenError):
    pass


def _now() -> str:
    return datetime.now().strftime("%Y%m%d-%H%M%S")


def _write_json(outdir: Path, name: str, value: Any) -> None:
    outdir.mkdir(parents=True, exist_ok=True)
    (outdir / f"{name}.json").write_text(
        json.dumps(value, ensure_ascii=False, indent=2), encoding="utf-8"
    )


class SterenClient:
    def __init__(self, host: str, user: str, password: str, iv: str, timeout: float = 20.0):
        if not shutil.which("openssl"):
            raise SterenError("Falta openssl en PATH (se usa para AES-128-CBC).")
        self.host = host
        self.user = user
        self.password = password
        self.iv = iv.encode()
        if len(self.iv) != 16:
            raise SterenError("STEREN_IV debe tener 16 bytes.")
        self.base = f"http://{host}"
        self.timeout = timeout
        self.jar = CookieJar()
        self.opener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(self.jar))
        self.stok: str | None = None
        self.sign: str | None = None

    def _open(
        self,
        method: str,
        path: str,
        *,
        body: bytes | None = None,
        headers: dict[str, str] | None = None,
    ) -> tuple[int, str, bytes]:
        h = {
            "User-Agent": "steren-config/1.0",
            "Accept": "application/json, text/javascript, */*; q=0.01",
            "Accept-Language": "es-MX,es;q=0.9",
            "Connection": "close",
        }
        if headers:
            h.update(headers)
        req = urllib.request.Request(self.base + path, data=body, headers=h, method=method)
        try:
            resp = self.opener.open(req, timeout=self.timeout)
            return resp.status, resp.geturl(), resp.read()
        except urllib.error.HTTPError as exc:
            return exc.code, exc.geturl(), exc.read()
        except OSError as exc:
            raise SterenError(f"No se pudo conectar a {self.host}: {exc}") from exc

    def _aes(self, data: bytes, sign: str, decrypt: bool = False) -> bytes:
        key = sign.encode().hex()
        args = ["openssl", "enc", "-aes-128-cbc", "-K", key, "-iv", self.iv.hex()]
        if decrypt:
            args.append("-d")
        proc = subprocess.run(args, input=data, capture_output=True)
        if proc.returncode != 0:
            raise SterenError(proc.stderr.decode("utf-8", "replace")[:200])
        return proc.stdout

    def _decrypt_payload(self, value: Any, sign: str) -> Any:
        if not isinstance(value, dict) or "data" not in value:
            return value
        raw = base64.b64decode(value["data"])
        return json.loads(self._aes(raw, sign, decrypt=True).decode("utf-8"))

    def login(self) -> None:
        self._open("GET", "/login.html")
        h = hashlib.md5(self.password.encode()).hexdigest().upper()
        body = json.dumps({"userName": self.user, "password": h}).encode()
        st, final_url, data = self._open(
            "POST",
            "/login/Auth",
            body=body,
            headers={
                "Content-Type": "application/json; charset=UTF-8",
                "Origin": self.base,
                "Referer": f"{self.base}/login.html",
                "X-Requested-With": "XMLHttpRequest",
            },
        )
        try:
            j = json.loads(data)
        except json.JSONDecodeError:
            j = None
        if isinstance(j, dict) and str(j.get("errCode")) == "0":
            self.stok = j.get("stok")
            self.sign = j.get("sign")
            if self.stok and self.sign:
                return
        if "index.html" in final_url or b"index.html" in data:
            self.stok = None
            self.sign = None
            self.stok_sign()
            return
        raise SterenAuthError(f"Login rechazado (HTTP {st}): {data[:120]!r}")

    def stok_sign(self) -> tuple[str, str]:
        st, _, data = self._open("GET", "/goform/stokCfg")
        if st != 200:
            raise SterenAuthError(f"stokCfg HTTP {st}")
        try:
            cfg = json.loads(data)["stokCfg"]
            self.stok = cfg["stok"]
            self.sign = cfg["sign"]
        except (json.JSONDecodeError, KeyError, TypeError) as exc:
            raise SterenAuthError("stokCfg invalido o sesion expirada") from exc
        return self.stok, self.sign

    def _ensure_session(self) -> None:
        if not self.stok or not self.sign:
            self.login()

    def get_module(self, name: str) -> Any:
        for attempt in range(2):
            self._ensure_session()
            stok, sign = self.stok_sign()
            path = (
                f"/;stok={urllib.parse.quote(stok, safe='')}/goform/getModules"
                f"?modules={urllib.parse.quote(name, safe='')}&rand={int(time.time() * 1000)}"
            )
            st, final_url, data = self._open("GET", path)
            if st != 200:
                raise SterenError(f"{name}: HTTP {st}")
            if b"login.html" in data[:500] or "login.html" in final_url:
                if attempt == 0:
                    self.login()
                    continue
                raise SterenAuthError(f"{name}: sesion expirada")
            try:
                value = json.loads(data)
            except json.JSONDecodeError as exc:
                raise SterenError(f"{name}: respuesta no JSON") from exc
            return self._decrypt_payload(value, sign)
        raise SterenError(f"{name}: no se pudo leer")

    def set_module(self, name: str, obj: dict[str, Any]) -> Any:
        for attempt in range(2):
            self._ensure_session()
            stok, sign = self.stok_sign()
            payload = json.dumps(
                {name: obj}, ensure_ascii=False, separators=(",", ":")
            ).encode()
            encrypted = base64.b64encode(self._aes(payload, sign)).decode()
            body = json.dumps({"data": encrypted}).encode()
            path = (
                f"/;stok={urllib.parse.quote(stok, safe='')}/goform/setModules"
                f"?modules={urllib.parse.quote(name, safe='')}"
            )
            st, final_url, data = self._open(
                "POST",
                path,
                body=body,
                headers={
                    "Content-Type": "application/json; charset=UTF-8",
                    "Origin": self.base,
                    "Referer": f"{self.base}/",
                    "X-Requested-With": "XMLHttpRequest",
                },
            )
            if b"login.html" in data[:500] or "login.html" in final_url:
                if attempt == 0:
                    self.login()
                    continue
                raise SterenAuthError(f"{name}: sesion expirada")
            try:
                value = json.loads(data)
            except json.JSONDecodeError as exc:
                raise SterenError(f"{name}: respuesta no JSON (HTTP {st})") from exc
            return self._decrypt_payload(value, sign)
        raise SterenError(f"{name}: no se pudo escribir")


def _sanitize_wifi(value: Any) -> dict[str, Any]:
    d = value if isinstance(value, dict) else {}
    return {k: v for k, v in d.items() if k not in SECRET_KEYS}


def _count_clients(value: Any) -> tuple[int, list[dict[str, Any]]]:
    nodes = value.get("deviceList", []) if isinstance(value, dict) else []
    out: list[dict[str, Any]] = []
    for node in nodes if isinstance(nodes, list) else []:
        for client in node.get("onlineList", []) if isinstance(node, dict) else []:
            if isinstance(client, dict):
                out.append(client)
    return len(out), out


def audit(client: SterenClient, outdir: Path) -> dict[str, Any]:
    results: dict[str, Any] = {}
    for name in AUDIT_MODULES:
        try:
            value = client.get_module(name)
            results[name] = value
            _write_json(outdir, name, value)
            print(f"  OK  {name}")
        except SterenError as exc:
            print(f"  --  {name} ({exc})")

    print("\nResumen STEREN")
    wan = results.get("wanStatus", {}) if isinstance(results.get("wanStatus"), dict) else {}
    if "wanStatus" in wan and isinstance(wan["wanStatus"], dict):
        wan = wan["wanStatus"]
    for key in ("connectStatus", "wanType", "wanIP", "wanGateway", "wanDns1", "wanDns2"):
        if key in wan:
            print(f"  WAN {key}: {wan[key]}")

    lan = results.get("lanCfg", {}) if isinstance(results.get("lanCfg"), dict) else {}
    if "lanCfg" in lan and isinstance(lan["lanCfg"], dict):
        lan = lan["lanCfg"]
    if lan:
        print(f"  LAN: {lan.get('lanIP')}/{lan.get('lanMask')} DHCP={lan.get('dhcpEn')} "
              f"{lan.get('startIP')}-{lan.get('endIP')} lease={lan.get('dhcpLeaseTime')}h "
              f"DNS={lan.get('lanDns1')}/{lan.get('lanDns2')}")

    basic = results.get("wifiBasicCfg", {}) if isinstance(results.get("wifiBasicCfg"), dict) else {}
    if "wifiBasicCfg" in basic and isinstance(basic["wifiBasicCfg"], dict):
        basic = basic["wifiBasicCfg"]
    basic = _sanitize_wifi(basic)
    if basic:
        print(f"  WiFi 2.4: SSID={basic.get('wifiSSID')} mode={basic.get('wifiSecurityMode')} "
              f"enabled={basic.get('wifiEn')}")
        print(f"  WiFi 5G : SSID={basic.get('wifiSSID_5g')} mode={basic.get('wifiSecurityMode_5g')} "
              f"enabled={basic.get('wifiEn_5g')}")

    adv = results.get("wifiAdvCfg", {}) if isinstance(results.get("wifiAdvCfg"), dict) else {}
    if "wifiAdvCfg" in adv and isinstance(adv["wifiAdvCfg"], dict):
        adv = adv["wifiAdvCfg"]
    if adv:
        print(f"  Radio: 2.4={adv.get('wifiMode')} ch={adv.get('wifiChannel')} "
              f"{adv.get('wifiBandwidth')}MHz | 5G={adv.get('wifiMode_5g')} "
              f"ch={adv.get('wifiChannel_5g')} {adv.get('wifiBandwidth_5g')}MHz")

    guest = results.get("wifiGuest", {}) if isinstance(results.get("wifiGuest"), dict) else {}
    if "wifiGuest" in guest and isinstance(guest["wifiGuest"], dict):
        guest = guest["wifiGuest"]
    if guest:
        print(f"  Guest: enabled={guest.get('guestEn')} 2.4={guest.get('guestSSID')} "
              f"5G={guest.get('guestSSID_5g')}")

    count, clients = _count_clients(results.get("deviceList"))
    print(f"  Clientes online: {count}")
    for c in sorted(clients, key=lambda x: str(x.get("ip", ""))):
        print(f"    {c.get('ip', ''):15} {c.get('connectType', ''):4} "
              f"{str(c.get('hostname', ''))[:28]:28} {c.get('mac', '')}")

    print(f"\nBackup/auditoria: {outdir}")
    return results


def _unwrap(value: Any, name: str) -> dict[str, Any]:
    if isinstance(value, dict) and name in value and isinstance(value[name], dict):
        return dict(value[name])
    if isinstance(value, dict):
        return dict(value)
    raise SterenError(f"{name}: se esperaba un objeto")


def apply_profile(client: SterenClient, profile: dict[str, Any], outdir: Path, yes: bool) -> None:
    bad = set(profile) & READ_ONLY_MODULES
    if bad:
        raise SterenError(f"No se pueden escribir modulos de solo lectura: {', '.join(sorted(bad))}")
    if not yes:
        print("DRY-RUN. Esto es lo que se aplicaria:")
        print(json.dumps(profile, ensure_ascii=False, indent=2))
        print("\nAgrega --yes para escribir en el router.")
        return

    print("Backup previo...")
    audit(client, outdir)

    # LAN al final: si cambia la IP, puede cortar la conexion.
    names = [n for n in profile if n != "lanCfg"]
    if "lanCfg" in profile:
        names.append("lanCfg")

    for name in names:
        patch = profile[name]
        if not isinstance(patch, dict):
            raise SterenError(f"{name}: la seccion debe ser un objeto")
        current = _unwrap(client.get_module(name), name)
        changed = sorted(k for k in patch if current.get(k) != patch[k])
        if not changed:
            print(f"  {name}: sin cambios")
            continue
        if set(patch) & SECRET_KEYS:
            print(f"  {name}: AVISO, cambia una clave")
        merged = {**current, **patch}
        print(f"  {name}: aplicando {', '.join(changed)}")
        response = client.set_module(name, merged)
        print(f"  {name}: respuesta {json.dumps(response, ensure_ascii=False)[:300]}")
    print("Aplicacion terminada.")


def _client_from_env() -> SterenClient:
    host = os.environ.get("STEREN_HOST", DEFAULT_HOST)
    user = os.environ.get("STEREN_USER", DEFAULT_USER)
    password = os.environ.get("STEREN_PASSWORD")
    iv = os.environ.get("STEREN_IV", DEFAULT_IV)
    if not password:
        raise SystemExit("Falta STEREN_PASSWORD en el entorno.")
    return SterenClient(host, user, password, iv)


def main() -> int:
    parser = argparse.ArgumentParser(description="Auditoria y configuracion del router Steren COM-870+")
    sub = parser.add_subparsers(dest="cmd", required=True)
    for name in ("audit", "backup"):
        p = sub.add_parser(name, help="Lee configuracion y guarda JSON")
        p.add_argument("--out", default=f"backups/steren-{name}-{_now()}")
    p = sub.add_parser("get", help="Lee un modulo y lo imprime")
    p.add_argument("module")
    p.add_argument("--out")
    p = sub.add_parser("apply", help="Aplica un perfil JSON")
    p.add_argument("profile")
    p.add_argument("--out", default=f"backups/steren-apply-{_now()}")
    p.add_argument("--yes", action="store_true", help="Escribe cambios (sin esto es dry-run)")
    args = parser.parse_args()

    try:
        client = _client_from_env()
        if args.cmd in ("audit", "backup"):
            audit(client, Path(args.out))
        elif args.cmd == "get":
            value = client.get_module(args.module)
            text = json.dumps(value, ensure_ascii=False, indent=2)
            if args.out:
                Path(args.out).write_text(text, encoding="utf-8")
                print(f"{args.module} -> {args.out}")
            else:
                print(text)
        elif args.cmd == "apply":
            profile = json.loads(Path(args.profile).read_text(encoding="utf-8"))
            apply_profile(client, profile, Path(args.out), args.yes)
        return 0
    except SterenAuthError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 2
    except (SterenError, OSError, json.JSONDecodeError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
