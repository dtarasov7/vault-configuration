"""Installer recovery and credential handling without modifying the host OS."""
import contextlib
import importlib.util
import io
import json
from pathlib import Path
import subprocess
import tempfile
import unittest
from types import SimpleNamespace
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[4]
(ROOT / '.work').mkdir(exist_ok=True)
SCRIPT = ROOT / 'scripts/deploy-test-vault-redos73.py'
specification = importlib.util.spec_from_file_location('test_lab_installer', SCRIPT)
installer = importlib.util.module_from_spec(specification)
specification.loader.exec_module(installer)


class FakeAPI:
    def __init__(self):
        self.initialized = False
        self.sealed = True
        self.auth = {}
        self.requests = []

    def request(self, method, path, payload=None, token=None, health=False):
        self.requests.append((method, path))
        if path == 'sys/health':
            return {'version': '2.0.4', 'initialized': self.initialized, 'sealed': self.sealed, 'cluster_id': 'fixture-cluster'}
        if path == 'sys/init':
            self.initialized = True
            return {'root_token': 'fixture-root-secret', 'keys_base64': ['fixture-unseal-secret']}
        if path == 'sys/unseal':
            self.sealed = False
            return {'sealed': False}
        if path == 'sys/auth':
            return {'data': self.auth}
        if path == 'sys/auth/userpass':
            self.auth['userpass/'] = {'type': 'userpass'}
        if path == 'auth/token/create':
            return {'auth': {'client_token': 'fixture-automation-secret'}}
        return {}


class InstallerTests(unittest.TestCase):
    def args(self):
        return SimpleNamespace(action='deploy', hostname='vault-test.example.org', port=18200,
                               policy=ROOT / 'roles/vault-configuration/files/bootstrap-policy.hcl')

    def test_bootstrap_is_persistent_and_does_not_print_credentials_or_create_kv_mounts(self):
        with tempfile.TemporaryDirectory(dir=str(ROOT / '.work')) as directory:
            private = Path(directory) / 'private'
            config = Path(directory) / 'config'
            api = FakeAPI()
            output = io.StringIO()
            with patch.object(installer, 'PRIVATE', private), patch.object(installer, 'CONFIG', config), contextlib.redirect_stdout(output):
                installer.bootstrap(self.args(), api)
                original = json.loads((private / 'access-vars.json').read_text())
                installer.bootstrap(self.args(), api)
            self.assertEqual(api.requests.count(('POST', 'sys/init')), 1)
            self.assertFalse(any(method == 'DELETE' or path.startswith('sys/mounts') for method, path in api.requests))
            for secret in ['fixture-root-secret', 'fixture-unseal-secret', 'fixture-automation-secret']:
                self.assertNotIn(secret, output.getvalue())
            self.assertEqual((private / 'operator-init.json').stat().st_mode & 0o777, 0o600)
            self.assertEqual((private / 'access-vars.json').stat().st_mode & 0o777, 0o600)
            current = json.loads((private / 'access-vars.json').read_text())
            self.assertEqual(current['vault_configuration_passwords'], original['vault_configuration_passwords'])

    def test_initialized_vault_without_local_keys_is_not_reset(self):
        with tempfile.TemporaryDirectory(dir=str(ROOT / '.work')) as directory:
            api = FakeAPI()
            api.initialized, api.sealed = True, False
            with patch.object(installer, 'PRIVATE', Path(directory)), self.assertRaises(installer.DeployError):
                installer.bootstrap(self.args(), api)
            self.assertNotIn(('POST', 'sys/init'), api.requests)

    def test_changed_cluster_id_is_rejected(self):
        with tempfile.TemporaryDirectory(dir=str(ROOT / '.work')) as directory:
            private = Path(directory)
            installer.write_file(private / 'operator-init.json', json.dumps({'root_token': 'fixture-root', 'keys_base64': ['fixture-key'], 'cluster_id': 'other-cluster'}))
            api = FakeAPI()
            api.initialized, api.sealed = True, False
            with patch.object(installer, 'PRIVATE', private), self.assertRaises(installer.DeployError):
                installer.bootstrap(self.args(), api)
            self.assertNotIn(('POST', 'auth/token/create'), api.requests)

    def test_existing_other_version_fails_read_only_preflight(self):
        args = self.args()
        args.check, args.listen_address = True, '0.0.0.0'
        args.rpm_url, args.rpm_sha256 = installer.RPM_URL, installer.RPM_SHA256
        original_read = Path.read_text
        def read(path, *arguments, **keywords):
            if str(path) == '/etc/os-release':
                return 'ID=redos\nVERSION_ID="7.3"\n'
            return original_read(path, *arguments, **keywords)
        with patch.object(Path, 'read_text', read), patch.object(installer.shutil, 'which', return_value='/usr/bin/fixture'), \
                patch.object(installer.subprocess, 'run', return_value=subprocess.CompletedProcess(['rpm'], 0, '2.0.0')) as commands:
            with self.assertRaises(installer.DeployError):
                installer.check_host(args)
            self.assertEqual(commands.call_count, 1)
            self.assertEqual(commands.call_args[0][0][0], 'rpm')
