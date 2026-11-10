"""RED OS 8 repository install/reuse and protected bootstrap without host changes."""
import contextlib
import importlib.util
import io
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

from test_installer import FakeAPI

ROOT = Path(__file__).resolve().parents[4]
(ROOT / '.work').mkdir(exist_ok=True)
spec = importlib.util.spec_from_file_location('vault_lab_redos8', ROOT / 'scripts/deploy-test-vault-redos8.py')
installer = importlib.util.module_from_spec(spec)
spec.loader.exec_module(installer)


class Redos8InstallerTests(unittest.TestCase):
    def test_installed_package_is_reused_without_dnf_or_version_pin(self):
        result = subprocess.CompletedProcess(['rpm'], 0, '1.21.2', '')
        with patch.object(installer.subprocess, 'run', return_value=result) as rpm, \
                patch.object(installer, 'command') as commands, contextlib.redirect_stdout(io.StringIO()):
            version = installer.install_package(None)
        self.assertEqual(version, '1.21.2')
        self.assertEqual(rpm.call_args[0][0], ['rpm', '-q', '--qf', '%{VERSION}', 'vault'])
        commands.assert_not_called()

    def test_missing_package_installs_by_name_from_configured_repositories(self):
        results = [subprocess.CompletedProcess(['rpm'], 1, '', 'not installed'),
                   subprocess.CompletedProcess(['rpm'], 0, '2.0.4', '')]
        with patch.object(installer.subprocess, 'run', side_effect=results), \
                patch.object(installer, 'command') as commands, contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(installer.install_package(None), '2.0.4')
        commands.assert_called_once_with(['dnf', '-y', 'install', 'vault'])

    def test_rpm_query_error_does_not_start_dnf(self):
        with patch.object(installer.subprocess, 'run', return_value=subprocess.CompletedProcess(['rpm'], 2, '', 'error')), \
                patch.object(installer, 'command') as commands:
            with self.assertRaises(installer.DeployError):
                installer.install_package(None)
        commands.assert_not_called()

    def test_dnf_must_actually_install_the_package(self):
        result = subprocess.CompletedProcess(['rpm'], 1, '', 'not installed')
        with patch.object(installer.subprocess, 'run', return_value=result), patch.object(installer, 'command'):
            with self.assertRaises(installer.DeployError):
                installer.install_package(None)

    def test_check_does_not_install_configure_or_bootstrap(self):
        for version in (None, '2.0.0'):
            with self.subTest(version=version), \
                    patch.object(sys, 'argv', ['deploy-test-vault-redos8.py', '--hostname', 'vault-test.example.org', '--check']), \
                    patch.object(installer, 'check_host'), patch.object(installer, 'installed_version', return_value=version), \
                    patch.object(installer, 'install_package') as install, patch.object(installer, 'configure_service') as configure, \
                    patch.object(installer, 'API') as api, contextlib.redirect_stdout(io.StringIO()):
                installer.main()
                install.assert_not_called()
                configure.assert_not_called()
                api.assert_not_called()

    def test_preflight_accepts_redos8_without_requiring_curl_or_exact_version(self):
        from types import SimpleNamespace
        args = SimpleNamespace(hostname='vault-test.example.org', port=8200, listen_address='0.0.0.0', check=True,
                               policy=ROOT / 'roles/vault-configuration/files/bootstrap-policy.hcl')
        original_read = Path.read_text
        def read(path, *arguments, **keywords):
            if str(path) == '/etc/os-release':
                return 'ID=redos\nVERSION_ID="8.0"\n'
            return original_read(path, *arguments, **keywords)
        with tempfile.TemporaryDirectory(dir=str(ROOT / '.work')) as directory, \
                patch.object(installer, 'CONFIG', Path(directory) / 'config'), \
                patch.object(installer, 'DATA', Path(directory) / 'data'), patch.object(Path, 'read_text', read), \
                patch.object(installer.shutil, 'which', return_value='/usr/bin/fixture') as which, \
                patch.object(installer.subprocess, 'run') as processes:
            installer.check_host(args)
        self.assertNotIn('curl', [call.args[0] for call in which.call_args_list])
        processes.assert_not_called()

    def test_bootstrap_accepts_matching_installed_version_and_preserves_passwords(self):
        from types import SimpleNamespace
        args = SimpleNamespace(action='deploy', hostname='vault-test.example.org', port=8200,
                               policy=ROOT / 'roles/vault-configuration/files/bootstrap-policy.hcl')
        class InstalledAPI(FakeAPI):
            def request(self, method, path, *arguments, **keywords):
                response = super().request(method, path, *arguments, **keywords)
                if path == 'sys/health':
                    response['version'] = '1.21.2'
                return response
        with tempfile.TemporaryDirectory(dir=str(ROOT / '.work')) as directory:
            private, config = Path(directory) / 'private', Path(directory) / 'config'
            output = io.StringIO()
            api = InstalledAPI()
            with patch.object(installer, 'PRIVATE', private), patch.object(installer, 'CONFIG', config), contextlib.redirect_stdout(output):
                installer.bootstrap(args, api, '1.21.2')
                first = json.loads((private / 'access-vars.json').read_text())
                installer.bootstrap(args, api, '1.21.2')
            second = json.loads((private / 'access-vars.json').read_text())
            self.assertEqual(first['vault_configuration_passwords'], second['vault_configuration_passwords'])
            self.assertEqual(api.requests.count(('POST', 'sys/init')), 1)
            self.assertEqual((private / 'operator-init.json').stat().st_mode & 0o777, 0o600)
            for secret in ('fixture-root-secret', 'fixture-unseal-secret', 'fixture-automation-secret'):
                self.assertNotIn(secret, output.getvalue())

    def test_mismatching_api_version_is_rejected_before_initialization(self):
        api = FakeAPI()
        with self.assertRaises(installer.DeployError):
            installer.bootstrap(None, api, '1.21.2')
        self.assertNotIn(('POST', 'sys/init'), api.requests)
