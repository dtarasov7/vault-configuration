"""TLS hostname/CA checks, redirects, timeouts and credential containment."""
import json
from pathlib import Path
import ssl
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from http.server import BaseHTTPRequestHandler, HTTPServer

from test_vault import ROOT
from vault_configuration.client import Client, VaultHTTPError


class TransportTests(unittest.TestCase):
    def serve(self, handler, context=None):
        server = HTTPServer(('127.0.0.1', 0), handler)
        if context:
            server.socket = context.wrap_socket(server.socket, server_side=True)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        self.addCleanup(thread.join, 5)
        self.addCleanup(server.server_close)
        self.addCleanup(server.shutdown)
        return server

    def test_redirect_never_forwards_token(self):
        received = []
        class Trap(BaseHTTPRequestHandler):
            def do_GET(self):
                received.append(self.headers.get('X-Vault-Token'))
                self.send_response(200)
                self.end_headers()
            def log_message(self, *args):
                return
        trap = self.serve(Trap)
        class Redirect(BaseHTTPRequestHandler):
            def do_GET(self):
                self.send_response(307)
                self.send_header('Location', 'http://127.0.0.1:' + str(trap.server_port) + '/v1/sys/health')
                self.end_headers()
            def log_message(self, *args):
                return
        redirect = self.serve(Redirect)
        client = Client({'address': 'http://127.0.0.1:' + str(redirect.server_port), 'timeout_seconds': 1, 'validate_tls': True}, 'test-sensitive-token')
        with self.assertRaises(VaultHTTPError):
            client.request('GET', 'sys/health')
        self.assertEqual(received, [])

    def test_tls_ca_hostname_and_timeout(self):
        with tempfile.TemporaryDirectory(prefix='vault-tls-', dir=str(ROOT / '.work')) as directory:
            key, cert = Path(directory) / 'key.pem', Path(directory) / 'cert.pem'
            subprocess.run(['openssl', 'req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-days', '1',
                            '-subj', '/CN=localhost', '-addext', 'subjectAltName=DNS:localhost',
                            '-keyout', str(key), '-out', str(cert)], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            class API(BaseHTTPRequestHandler):
                def do_GET(self):
                    if self.path.endswith('slow'):
                        time.sleep(0.2)
                    self.send_response(200)
                    self.end_headers()
                    try:
                        self.wfile.write(b'{"data": {"ok": true}}')
                    except (BrokenPipeError, ssl.SSLError):
                        return
                def log_message(self, *args):
                    return
            context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            context.load_cert_chain(str(cert), str(key))
            server = self.serve(API, context)
            connection = {'address': 'https://localhost:' + str(server.server_port), 'timeout_seconds': 1,
                          'validate_tls': True, 'ca_file': str(cert)}
            client = Client(connection, 'test-sensitive-token')
            self.assertTrue(client.read('sys/health')['ok'])
            untrusted = dict(connection)
            untrusted.pop('ca_file')
            with self.assertRaises(VaultHTTPError):
                Client(untrusted, 'test-sensitive-token').request('GET', 'sys/health')
            mismatch = dict(connection, address='https://127.0.0.1:' + str(server.server_port))
            with self.assertRaises(VaultHTTPError):
                Client(mismatch, 'test-sensitive-token').request('GET', 'sys/health')
            client.timeout = 0.05
            with self.assertRaises(VaultHTTPError) as raised:
                client.request('GET', 'slow')
            self.assertNotIn('test-sensitive-token', str(raised.exception))
