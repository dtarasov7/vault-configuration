"""Safe LDIF, credentials and preflight for the standalone RED OS LDAP seeder."""
import base64
import hashlib
import contextlib
import io
import subprocess
import sys
import importlib.util
import json
import os
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[4]
(ROOT / '.work').mkdir(exist_ok=True)
spec = importlib.util.spec_from_file_location('ldap_seed', ROOT / 'scripts/seed-test-ldap-redos8.py')
seed = importlib.util.module_from_spec(spec)
spec.loader.exec_module(seed)


class SeedUnitTests(unittest.TestCase):
    def args(self, directory):
        return SimpleNamespace(domain='example.org', hostname='ldap-test.example.org',
                               state_dir=Path(directory) / 'private', data_dir=Path(directory) / 'data',
                               schema_dir=Path(directory) / 'schema', check=True)

    def test_domain_validation_and_nested_private_path_rejection(self):
        with tempfile.TemporaryDirectory(dir=str(ROOT / '.work')) as directory:
            args = self.args(directory)
            self.assertEqual(seed.validate_arguments(args), 'dc=example,dc=org')
            for domain in ['example.org\nolcRootDN: evil', 'a,,b.org', 'example..org', '../example.org']:
                args.domain = domain
                with self.assertRaises(seed.SeedError):
                    seed.validate_arguments(args)
            args.domain = 'example.org'
            args.state_dir = args.data_dir / 'secrets'
            with self.assertRaises(seed.SeedError):
                seed.validate_arguments(args)

    def test_ldif_roundtrip_with_unicode_and_newlines(self):
        text = seed.ldif_entry('cn=разработчики,dc=example,dc=org',
                               {'description': ['a\nb: c'], 'objectClass': ['top', 'groupOfNames']})
        entries = seed.parse_ldif(text)
        self.assertEqual(entries[0]['description'], ['a\nb: c'])
        self.assertEqual(entries[0]['dn'], ['cn=разработчики,dc=example,dc=org'])
        self.assertEqual(seed.parse_ldif('dn: dc=example,dc=org\ndescription: hel\n lo\n'),
                         [{'dn':['dc=example,dc=org'], 'description':['hello']}])

    def test_ssha_is_salted_and_matches_password(self):
        value = seed.password_hash('fixture-password')
        raw = base64.b64decode(value[len('{SSHA}'):])
        self.assertEqual(hashlib.sha1(b'fixture-password' + raw[20:]).digest(), raw[:20])
        self.assertNotEqual(value, seed.password_hash('fixture-password'))

    def test_private_outputs_match_role_inputs(self):
        with tempfile.TemporaryDirectory(dir=str(ROOT / '.work')) as directory:
            args = self.args(directory)
            state = {'base_dn':'dc=example,dc=org', 'passwords':dict.fromkeys(['vault'] + list(seed.USERS), 'fixture-secret')}
            seed.write_outputs(args, state)
            for file in args.state_dir.iterdir():
                self.assertEqual(file.stat().st_mode & 0o777, 0o600)
            variables = json.loads((args.state_dir / 'ldap-vars.json').read_text())
            self.assertNotIn('fixture-secret', json.dumps(variables))
            self.assertEqual(variables['vault_configuration_ldap'][0]['auth_mount'], 'ldap')
            self.assertEqual(variables['vault_configuration_ldap'][0]['config']['userattr'], 'uid')
            credentials = json.loads((args.state_dir / 'ldap-secrets.json').read_text())
            self.assertEqual(credentials['vault_configuration_ldap_passwords']['test-ldap'], 'fixture-secret')

    def test_password_is_in_temporary_file_not_process_arguments(self):
        with tempfile.TemporaryDirectory(dir=str(ROOT / '.work')) as directory:
            ldap = seed.LDAP(Path(directory))
            paths = []
            def execute(tool, arguments, **kwargs):
                self.assertNotIn('fixture-secret', arguments)
                filename = Path(arguments[arguments.index('-y') + 1])
                paths.append(filename)
                self.assertEqual(filename.read_text(), 'fixture-secret')
                self.assertEqual(filename.stat().st_mode & 0o777, 0o600)
                return SimpleNamespace(stdout='ok')
            with patch.object(ldap, 'execute', execute):
                ldap.bound('ldapwhoami', 'cn=vault,dc=example,dc=org', 'fixture-secret', [])
            self.assertTrue(all(not path.exists() for path in paths))

    def test_unmanaged_existing_suffix_is_not_taken_over(self):
        database = {'dn':['olcDatabase={2}mdb,cn=config'], 'olcsuffix':['dc=example,dc=org']}
        ldap = SimpleNamespace(search=lambda *args, **kwargs: [database])
        with tempfile.TemporaryDirectory(dir=str(ROOT / '.work')) as directory:
            with self.assertRaises(seed.SeedError):
                seed.discover(ldap, self.args(directory), 'dc=example,dc=org', None)

    def test_check_with_stopped_service_does_not_start_or_write(self):
        with tempfile.TemporaryDirectory(dir=str(ROOT / '.work')) as directory:
            args = self.args(directory)
            arguments = ['seed-test-ldap-redos8.py', '--hostname', args.hostname, '--state-dir', str(args.state_dir),
                         '--data-dir', str(args.data_dir), '--check']
            with patch.object(sys, 'argv', arguments), patch.object(seed, 'check_host'),                     patch.object(seed.subprocess, 'run', return_value=subprocess.CompletedProcess(['systemctl'], 3)) as calls,                     patch.object(seed, 'seed') as apply, contextlib.redirect_stdout(io.StringIO()):
                seed.main()
            self.assertEqual(calls.call_count, 1)
            self.assertEqual(calls.call_args[0][0], ['systemctl', 'is-active', '--quiet', 'slapd'])
            apply.assert_not_called()
            self.assertFalse(args.state_dir.exists())
            self.assertFalse(args.data_dir.exists())

    def test_redos7_is_rejected_before_service_or_ldap_commands(self):
        original = Path.read_text
        def read(path, *arguments, **keywords):
            if str(path) == '/etc/os-release':
                return 'ID=redos\nVERSION_ID="7.3"\n'
            return original(path, *arguments, **keywords)
        with patch.object(Path, 'read_text', read), patch.object(seed.os, 'geteuid', return_value=0),                 patch.object(seed.subprocess, 'run') as calls:
            with self.assertRaises(seed.SeedError):
                seed.check_host(None)
            calls.assert_not_called()

    def test_state_rejects_public_permissions_and_symlinks(self):
        with tempfile.TemporaryDirectory(dir=str(ROOT / '.work')) as directory:
            filename = Path(directory) / 'state.json'
            seed.atomic_write(filename, '{}')
            self.assertEqual(seed.read_private(filename), {})
            filename.chmod(0o644)
            with self.assertRaises(seed.SeedError):
                seed.read_private(filename)
            link = Path(directory) / 'symlink'
            link.symlink_to(filename)
            with self.assertRaises(seed.SeedError):
                seed.atomic_write(link, 'replacement')
