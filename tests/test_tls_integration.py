"""Real loopback mTLS handshake with ephemeral synthetic certificates only."""

import datetime
import json
import ssl
import tempfile
import threading
import unittest
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from unittest.mock import patch

from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

from xiaomi_nas_ssh import api as api_module
from xiaomi_nas_ssh.api import AdminAPI, NasError
from xiaomi_nas_ssh.bootstrap import bootstrap


class MutualTLSIntegrationTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        now = datetime.datetime.now(datetime.timezone.utc)
        ca_key = Ed25519PrivateKey.generate()
        ca_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Synthetic test CA")])
        ca = (
            x509.CertificateBuilder()
            .subject_name(ca_name)
            .issuer_name(ca_name)
            .public_key(ca_key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - datetime.timedelta(days=1))
            .not_valid_after(now + datetime.timedelta(days=1))
            .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
            .add_extension(
                x509.KeyUsage(False, False, False, False, False, True, True, False, False),
                critical=True,
            )
            .add_extension(
                x509.SubjectKeyIdentifier.from_public_key(ca_key.public_key()), critical=False
            )
            .sign(ca_key, None)
        )
        (self.root / "ca_chain.pem").write_bytes(ca.public_bytes(serialization.Encoding.PEM))

        def issue(name, cn, server=False):
            key = Ed25519PrivateKey.generate()
            cert = (
                x509.CertificateBuilder()
                .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)]))
                .issuer_name(ca_name)
                .public_key(key.public_key())
                .serial_number(x509.random_serial_number())
                .not_valid_before(now - datetime.timedelta(days=1))
                .not_valid_after(now + datetime.timedelta(days=1))
                .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
                .add_extension(
                    x509.KeyUsage(True, False, False, False, False, False, False, False, False),
                    critical=True,
                )
                .add_extension(
                    x509.ExtendedKeyUsage(
                        [
                            ExtendedKeyUsageOID.SERVER_AUTH
                            if server
                            else ExtendedKeyUsageOID.CLIENT_AUTH
                        ]
                    ),
                    critical=False,
                )
                .add_extension(
                    x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_key.public_key()),
                    critical=False,
                )
                .add_extension(x509.SubjectAlternativeName([x509.DNSName(cn)]), critical=False)
                .sign(ca_key, None)
            )
            (self.root / (name + "_cert.pem")).write_bytes(
                cert.public_bytes(serialization.Encoding.PEM)
            )
            (self.root / (name + "_private_key.pem")).write_bytes(
                key.private_bytes(
                    serialization.Encoding.PEM,
                    serialization.PrivateFormat.PKCS8,
                    serialization.NoEncryption(),
                )
            )

        issue("client", "nas.123456789.a1b2c3.1")
        server_dir = self.root / "server"
        server_dir.mkdir()
        issue("server/host", "nas.123456789.a1b2c3.0", True)
        self.routes = []
        routes = self.routes

        class Handler(BaseHTTPRequestHandler):
            def do_POST(self):
                self.rfile.read(int(self.headers.get("Content-Length", 0)))
                routes.append(self.path)
                data = (
                    {"version": api_module.SUPPORTED_VERSION}
                    if self.path.endswith("get_system_version")
                    else {
                        "account": [
                            {
                                "id": "1",
                                "username": "synthetic-owner",
                                "password": "synthetic-not-public-output",
                            }
                        ]
                    }
                )
                body = json.dumps({"code": 0, "data": data}).encode()
                self.send_response(200)
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def log_message(self, *args):
                pass

        self.server = HTTPServer(("127.0.0.1", 0), Handler)
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.load_cert_chain(
            str(server_dir / "host_cert.pem"), str(server_dir / "host_private_key.pem")
        )
        ctx.load_verify_locations(str(self.root / "ca_chain.pem"))
        ctx.verify_mode = ssl.CERT_REQUIRED
        self.server.socket = ctx.wrap_socket(self.server.socket, server_side=True)
        thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        thread.start()
        self.addCleanup(self.server.server_close)
        self.addCleanup(self.server.shutdown)
        real_connection = api_module._Connection

        def connection(host, port, server_name, context):
            return real_connection("127.0.0.1", self.server.server_port, server_name, context)

        route = patch.object(api_module, "_Connection", side_effect=connection)
        route.start()
        self.addCleanup(route.stop)

    def test_read_only_plan_uses_real_mutual_tls_and_never_creates_state(self):
        api = AdminAPI.from_directory("10.23.45.67", self.root)
        result = bootstrap(api, "unused", self.root / "must-not-exist")
        self.assertTrue(result["mutual_tls_verified"])
        self.assertTrue(result["supported_firmware"])
        self.assertFalse(result["device_changes"])
        self.assertEqual(len(self.routes), 2)
        self.assertFalse((self.root / "must-not-exist").exists())
        self.assertNotIn("synthetic-not-public-output", json.dumps(result))

    def test_wrong_server_identity_is_rejected_without_disabling_tls(self):
        api = AdminAPI.from_directory("10.23.45.67", self.root)
        api._server_name = "wrong.example.invalid"
        with self.assertRaises(NasError):
            api.version()
        self.assertEqual(self.routes, [])

    def test_missing_client_certificate_is_rejected(self):
        api = AdminAPI.from_directory("10.23.45.67", self.root)
        api._context = ssl.create_default_context(cafile=str(self.root / "ca_chain.pem"))
        with self.assertRaises(NasError):
            api.version()
        self.assertEqual(self.routes, [])
