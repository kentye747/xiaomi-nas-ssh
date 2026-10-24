"""Small mTLS client. Errors intentionally exclude response bodies and credentials."""
import base64
import http.client
import ipaddress
import json
import re
import socket
import ssl
from pathlib import Path
from urllib.parse import quote

from cryptography import x509
from cryptography.x509.oid import NameOID

SUPPORTED_VERSION = "1.0.9.462.F24C26D24-REL"


class NasError(RuntimeError):
    """A message suitable for local display, without raw device responses."""


def lan_ipv4(value):
    try:
        address = ipaddress.IPv4Address(value)
    except ipaddress.AddressValueError:
        raise NasError("Use a single LAN IPv4 address.") from None
    networks = ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16")
    if not any(address in ipaddress.IPv4Network(n) for n in networks):
        raise NasError("Bootstrap is restricted to private LAN addresses.")
    return str(address)


class _Connection(http.client.HTTPSConnection):
    def __init__(self, address, port, server_name, context):
        super().__init__(address, port, timeout=20, context=context)
        self._server_name = server_name

    def connect(self):
        raw = socket.create_connection((self.host, self.port), self.timeout)
        try:
            self.sock = self._context.wrap_socket(raw, server_hostname=self._server_name)
        except BaseException:
            raw.close()
            raise


class AdminAPI:
    def __init__(self, host, certificate, private_key, ca):
        self.host = lan_ipv4(host)
        if ssl.OPENSSL_VERSION.startswith("LibreSSL"):
            raise NasError("Use Python 3.11+ linked to modern OpenSSL, not legacy LibreSSL.")
        cert = x509.load_pem_x509_certificate(Path(certificate).read_bytes())
        names = cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
        match = re.fullmatch(r"nas\.([0-9]+)\.([0-9a-f]+)(?:\.[0-9]+)?", names[0].value) if names else None
        if not match:
            raise NasError("Client certificate CN has an unsupported format.")
        self.uid = match[1]
        self._server_name = f"nas.{match[1]}.{match[2]}.0"
        self._context = ssl.create_default_context(cafile=str(ca))
        self._context.load_cert_chain(str(certificate), str(private_key))

    @classmethod
    def from_directory(cls, host, directory):
        directory = Path(directory).expanduser()
        certs = sorted(directory.glob("*_cert.pem"))
        if len(certs) != 1:
            raise NasError("Certificate directory must contain exactly one client certificate.")
        cert = certs[0]
        key = directory / (cert.name.removesuffix("_cert.pem") + "_private_key.pem")
        return cls(host, cert, key, directory / "ca_chain.pem")

    def _request(self, method, port, path, body=b"", headers=None):
        connection = _Connection(self.host, port, self._server_name, self._context)
        try:
            connection.request(method, path, body=body, headers={"Connection": "close", **(headers or {})})
            response = connection.getresponse()
            data = response.read(1024 * 1024 + 1)
            if len(data) > 1024 * 1024:
                raise NasError("Management response exceeds the size limit.")
            return response.status, data
        except (OSError, http.client.HTTPException):
            raise NasError("Management connection failed; inspect certificates and LAN access locally.") from None
        finally:
            connection.close()

    def call(self, route, body=None):
        allowed = {"system/get_system_version", "netshare/get_samba_account", "filemgr/get_pool_info",
                   "netshare/add_samba_account", "netshare/set_samba_account"}
        if route not in allowed:
            raise NasError("Management route is outside this tool's allowlist.")
        status, data = self._request("POST", 443, "/cgi-bin/luci/" + route,
                                     json.dumps(body or {}).encode(), {"Content-Type": "application/json"})
        try:
            result = json.loads(data)
        except (ValueError, UnicodeError):
            raise NasError("Management response is not valid JSON.") from None
        if status != 200 or not isinstance(result, dict) or result.get("code") != 0:
            raise NasError("Management API rejected the request; raw response suppressed.")
        return result.get("data")

    def accounts(self):
        data = self.call("netshare/get_samba_account")
        rows = data.get("account") if isinstance(data, dict) else None
        if not isinstance(rows, list) or not all(isinstance(r, dict) for r in rows):
            raise NasError("Unsupported Samba account schema.")
        return rows

    def version(self):
        return self.call("system/get_system_version").get("version")

    def make_directory(self, name):
        data = self.call("filemgr/get_pool_info", {"selector": ["webDAV"]})
        credentials = data.get("webDAV", {})
        if not all(isinstance(credentials.get(k), str) for k in ("username", "password")):
            raise NasError("Authenticated WebDAV access is unavailable.")
        basic = base64.b64encode((credentials["username"] + ":" + credentials["password"]).encode()).decode()
        status, _ = self._request("MKCOL", 5000, "/pool0/data/" + quote(name, safe="") + "/",
                                  headers={"Authorization": "Basic " + basic})
        if status != 201:
            raise NasError("A new temporary staging directory could not be created.")
