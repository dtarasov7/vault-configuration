"""Run with python3 -m unittest discover -s roles/vault-configuration/tests/unit -v."""
import copy
import errno
import io
import json
import os
from pathlib import Path
import stat
import socket
import ssl
import sys
import tempfile
import unittest
from unittest.mock import Mock, patch
from urllib.error import HTTPError, URLError

ROLE = Path(__file__).resolve().parents[2]
(ROLE.parents[1] / '.work').mkdir(exist_ok=True)
sys.path.insert(0, str(ROLE / 'module_utils'))
from vault_configuration.common import ConfigurationError, digest, public
from vault_configuration.compiler import compile_grant, compile_personal, parse_rules, path, reverse, policy_name
from vault_configuration.validation import validate
from vault_configuration.planner import Planner, resolve
from vault_configuration.adapters import KubernetesAdapter, JWTAdapter, AppRoleAdapter
from vault_configuration.client import Client, NoRedirect, VaultHTTPError
from vault_configuration.runner import summaries, run
from vault_configuration.reader import snapshot


def config(directory='/test'):
    return {'connection': {'address': 'https://vault.example.org'},
            'management': {'owner': 'test', 'policy_prefix': 'vam-test-'}}


def grant(permissions=None, logical='payments/prod', scope='subtree'):
    return {'id': 'access', 'subjects': [{'kind': 'user', 'id': 'alice'}],
            'paths': [{'mount': 'apps', 'path': logical, 'scope': scope, 'permissions': permissions or ['read']}]}


def user():
    return {'id': 'alice', 'name': 'alice', 'source': 'external'}


def view():
    return {'cluster_id': 'cluster', 'version': '2.0.0', 'mounts': {name + '/': {'type':'kv','options':{'version':'2'}} for name in ['certs','infra','apps','cicd','users']}, 'auth': {}, 'objects': {},
            'entities': {}, 'groups': {}, 'policies': {}, 'aliases': {}, 'userpass': {}, 'roles': {}, 'automation_entity': ''}




class CompatibilityTests(unittest.TestCase):
    def client(self, version):
        client = Mock()
        client.request.return_value = {'initialized': True, 'sealed': False,
                                       'cluster_id': 'cluster', 'version': version}
        client.read.return_value = {}
        client.list.return_value = []
        return client

    def test_only_vault_two_is_supported_before_discovery(self):
        settings, _ = validate(config(), {}, {})
        for version in ('1.21.3', '3.0.0', '12.0.0', '2.0', '2.invalid', None, True):
            with self.subTest(version=version):
                client = self.client(version)
                with self.assertRaisesRegex(ConfigurationError, 'Only Vault 2.x'):
                    snapshot(client, settings)
                client.read.assert_not_called()

    def test_tested_versions_are_quiet_and_other_two_versions_warn(self):
        settings, _ = validate(config(), {}, {})
        for version in ('2.0.0', '2.0.4', '2.0.5', '2.0.999', '2.0.4+vendor'):
            self.assertEqual(snapshot(self.client(version), settings)['warnings'], [])
        for version in ('2.1.0', '2.15.42', '2.1.0-rc1'):
            with self.subTest(version=version):
                actual = snapshot(self.client(version), settings)
                self.assertEqual(actual['warnings'][0]['kind'], 'compatibility')
                self.assertEqual(actual['warnings'][0]['version'], version)

    def test_warning_survives_dry_apply_and_export(self):
        with tempfile.TemporaryDirectory(dir=str(ROLE.parents[1] / '.work')) as directory:
            for mode in ('dry', 'apply', 'export'):
                with self.subTest(mode=mode):
                    settings = config(directory)
                    settings['mode'] = mode
                    settings['mounts'] = []
                    options = {'destination': directory + '/export.yml'} if mode == 'export' else None
                    result = run(settings, {}, 'test-token', export=options, client=self.client('2.1.0'))
                    self.assertIn('Vault 2.1.0 is outside the validated 2.0.x series', result['warnings'][0])
                    if mode != 'export':
                        self.assertEqual(result['plan']['warnings'][0]['kind'], 'compatibility')

    def test_removed_configuration_options_are_rejected(self):
        for key, value in (('schema_version', 1), ('compatibility_profile', 'community-validated')):
            settings = config()
            settings[key] = value
            with self.assertRaises(ConfigurationError):
                validate(settings, {}, {})


class CompilerTests(unittest.TestCase):
    def test_reject_unsafe_paths(self):
        for value in ['', '/prod', 'prod/', 'a//b', '.', '..', 'a/..', 'a/./b', 'a\\b', 'a%2fb', 'a*', 'a+', 'a\nb', 'прод', '{{identity.entity.id}}']:
            with self.subTest(path=value), self.assertRaises(ConfigurationError):
                path(value)

    def test_boundary_exact_subtree(self):
        rules = parse_rules(compile_grant(grant()))
        self.assertEqual(set(rules), {'apps/data/payments/prod', 'apps/data/payments/prod/*'})
        self.assertNotIn('apps/data/payments/prod*', rules)
        exact = parse_rules(compile_grant(grant(scope='exact')))
        self.assertEqual(len(exact), 1)

    def test_determinism_and_no_implicit_parents(self):
        item = grant(['list', 'write', 'read'])
        item['paths'].append(dict(item['paths'][0], path='prod/payments/data/backend'))
        expected = compile_grant(item)
        item['paths'].reverse()
        item['paths'][0]['permissions'].reverse()
        self.assertEqual(compile_grant(item), expected)
        self.assertNotIn('apps/metadata/payments"', expected)
        self.assertIn('prod/payments/data/backend', expected)

    def test_permissions_are_separate(self):
        read = compile_grant(grant())
        write = compile_grant(grant(['write']))
        self.assertNotIn('delete', read)
        self.assertNotIn('destroy', write)
        operations = {'delete_latest': 'data', 'delete_versions': 'delete', 'undelete_versions': 'undelete',
                      'destroy_versions': 'destroy', 'delete_metadata': 'metadata'}
        for permission, api in operations.items():
            rules = parse_rules(compile_grant(grant([permission], scope='exact')))
            self.assertEqual(len(rules), 1)
            self.assertTrue(next(iter(rules)).startswith('apps/' + api + '/'))

    def test_personal_literals(self):
        personal = {'enabled': True, 'mount': 'users', 'permissions': ['read', 'write', 'list', 'delete_latest']}
        text = compile_personal(personal)
        self.assertIn('{{identity.entity.id}}/*', text)
        self.assertNotIn('path "users/metadata/"', text)
        exported = reverse(text, ['users'])
        self.assertEqual(parse_rules(compile_personal(exported['personal'])), parse_rules(text))

    def test_ldap_personal_literals_and_reverse(self):
        personal = {'enabled': True, 'mount': 'users', 'identity_source': 'ldap_login',
                    'auth_mount': 'directory/ldap', 'path_prefix': 'dep1', 'permissions': ['read', 'write', 'list']}
        text = compile_personal(personal, 'auth_ldap_test')
        self.assertIn('users/data/dep1/{{identity.entity.aliases.auth_ldap_test.name}}/*', text)
        self.assertIn('users/metadata/dep1/{{identity.entity.aliases.auth_ldap_test.name}}/*', text)
        self.assertNotIn('identity.entity.id', text)
        converted = reverse(text, ['users'])['personal']
        self.assertEqual(converted['identity_source'], 'ldap_login')
        self.assertEqual(converted['path_prefix'], 'dep1')
        self.assertEqual(converted['auth_accessor'], 'auth_ldap_test')
        self.assertEqual(parse_rules(compile_personal(converted, converted['auth_accessor'])), parse_rules(text))
        for prefix in ['', 'department/team']:
            item = dict(personal, path_prefix=prefix)
            policy = compile_personal(item, 'auth_ldap_test')
            self.assertEqual(reverse(policy, ['users'])['personal']['path_prefix'], prefix)
        for prefix in ['../dep1', 'dep1/', 'dep1/*', '{{identity.entity.name}}']:
            with self.subTest(prefix=prefix), self.assertRaises(ConfigurationError):
                compile_personal(dict(personal, path_prefix=prefix), 'auth_ldap_test')
        for accessor in [None, 'unsafe.accessor', 'bad/segment', 'bad}}/*']:
            with self.subTest(accessor=accessor), self.assertRaises(ConfigurationError):
                compile_personal(personal, accessor)
        mixed = text + compile_personal({'mount': 'users', 'permissions': ['read']})
        with self.assertRaises(ConfigurationError):
            reverse(mixed, ['users'])

    def test_roundtrip_supported_acl(self):
        for permissions in [['read'], ['read', 'write', 'list'], ['patch', 'update_metadata', 'read_metadata'],
                            ['delete_latest', 'delete_versions', 'undelete_versions', 'destroy_versions', 'delete_metadata']]:
            item = grant(permissions)
            item['discovery_paths'] = [{'mount': 'apps', 'path': 'payments'}]
            text = compile_grant(item)
            exported = reverse(text, ['apps'])
            self.assertEqual(parse_rules(compile_grant(exported)), parse_rules(text))

    def test_export_rejects_unsupported_hcl(self):
        texts = ['path "apps/data/prod*" { capabilities = ["read"] }',
                 'path "apps/data/prod" { capabilities = ["deny"] }',
                 'path "apps/data/prod" { capabilities = ["create"] }',
                 'path "apps/data/prod" { capabilities = ["read"] allowed_parameters = {} }']
        for text in texts:
            with self.subTest(text=text), self.assertRaises(ConfigurationError):
                reverse(text, ['apps'])

    def test_root_scope_roundtrip_requires_explicit_validation_opt_in(self):
        item = grant(['read', 'list'], logical='')
        text = compile_grant(item)
        exported = reverse(text, ['apps'])
        self.assertEqual(parse_rules(compile_grant(exported)), parse_rules(text))

    def test_unique_policy_names(self):
        self.assertNotEqual(policy_name('vam-', 'prod'), policy_name('vam-', 'production'))


class ValidationTests(unittest.TestCase):
    def invalid(self, sections=None, update=None):
        configuration = config()
        if update:
            update(configuration)
        with self.assertRaises(ConfigurationError):
            validate(configuration, sections or {}, {})

    def test_unknown_fields_and_types(self):
        self.invalid(update=lambda value: value.update(unknown=True))
        self.invalid(update=lambda value: value.update(safety={'max_deletions': True}))
        self.invalid({'users': [dict(user(), groups=['x'])]})
        self.invalid({'users': [dict(user(), disabled='false')]})
        self.invalid({'users': [user(), user()]})

    def test_references_and_cycles(self):
        self.invalid({'users': [user()], 'grants': [dict(grant(), subjects=[{'kind': 'group', 'id': 'missing'}])]})
        self.invalid({'groups': [{'id': 'a', 'name': 'a', 'type': 'internal', 'member_groups': ['b']},
                                 {'id': 'b', 'name': 'b', 'type': 'internal', 'member_groups': ['a']}]})
        self.invalid({'groups': [{'id': 'x', 'name': 'x', 'type': 'external', 'members': []}]})

    def test_root_list_and_destructive_guards(self):
        self.invalid({'users': [user()], 'grants': [grant(['list'], scope='exact')]})
        self.invalid({'users': [user()], 'grants': [grant(logical='')]})
        self.invalid({'users': [user()], 'grants': [grant(['destroy_versions'])]})
        self.invalid({'users': [user()], 'grants': [dict(grant(), discovery_paths=[{'mount': 'apps', 'path': ''}])]})
        self.invalid({'users': [user()], 'grants': [{'id': 'x', 'subjects': [{'kind': 'user', 'id': 'alice'}], 'existing_policies': ['root']}]})

    def test_empty_and_omitted(self):
        conf, sections = validate(config(), {'users': None, 'groups': []}, {})
        self.assertIsNone(sections['users'])
        self.assertEqual(sections['groups'], [])
        validate(config(), {'users': []}, {})

    def test_duplicate_bindings_members_and_subjects(self):
        first = dict(user(), source='userpass', auth_mount='userpass', login='alice')
        second = dict(first, id='other', name='other')
        self.invalid({'users': [first, second]})
        self.invalid({'users': [user()], 'grants': [dict(grant(), subjects=[{'kind':'user','id':'alice'}] * 2)]})
        self.invalid({'users': [user()], 'groups': [{'id':'dev','name':'dev','type':'internal','members':['alice','alice']}]})

    def test_ldap_transport_choice_revision_and_known_fields(self):
        base = {'id':'ad','auth_mount':'ad','config':{'url':'ldap://dc.example.org','userdn':'dc=example,dc=org','groupdn':'dc=example,dc=org'}}
        self.invalid({'ldap':[copy.deepcopy(base)]})
        plain = copy.deepcopy(base)
        plain['auth_mount'] = 'ldap'
        plain['config']['url'] = 'ldap://dc.example.org:3268'
        plain['config']['starttls'] = False
        plain['allow_insecure_ldap'] = True
        validate(config(), {'ldap':[plain]}, {})
        starttls = copy.deepcopy(base)
        starttls['config']['starttls'] = True
        validate(config(), {'ldap':[starttls]}, {})
        base['config']['url'] = 'ldaps://dc.example.org'
        validate(config(), {'ldap':[copy.deepcopy(base)]}, {})
        base['config']['binddn'] = 'cn=vault,dc=example,dc=org'
        validate(config(), {'ldap':[copy.deepcopy(base)]}, {})
        base['bind_password_policy'] = 'on_create'
        base['config']['bindpass'] = 'must-be-external'
        self.invalid({'ldap':[base]})

    def test_directory_aliases_allow_unicode_but_reject_control_characters(self):
        validate(config(), {'groups':[{'id':'sre','name':'sre','type':'external',
                                      'alias':{'auth_mount':'ad','name':'Администраторы проекта'}}]}, {})
        self.invalid({'groups':[{'id':'sre','name':'sre','type':'external',
                                'alias':{'auth_mount':'ad','name':'group\nname'}}]})

    def test_tls_origin(self):
        for address in ['http://vault.example.org', 'https://token@vault.example.org', 'https://vault.example.org/v1',
                        'https://vault.example.org?token=secret']:
            self.invalid(update=lambda value: value['connection'].update(address=address))




class AdapterTests(unittest.TestCase):
    def test_kubernetes_preserves_bindings(self):
        current = {'bound_service_account_names': ['backend'], 'bound_service_account_namespaces': ['prod'],
                   'audience': 'vault', 'token_ttl': 300, 'token_policies': ['foreign']}
        payload = KubernetesAdapter.payload(current, ['foreign', 'new'])
        for key in current.keys() - {'token_policies'}:
            self.assertEqual(payload[key], current[key])

    def test_jwt_preserves_claims(self):
        current = {'user_claim': 'sub', 'bound_claims': {'project': ['payments']}, 'bound_audiences': ['vault'],
                   'claim_mappings': {'team': 'team'}, 'token_ttl': 400}
        payload = JWTAdapter.payload(current, ['new'])
        for key in current:
            self.assertEqual(payload[key], current[key])
        with self.assertRaises(ConfigurationError):
            JWTAdapter.payload(dict(current, future_constraint=True), [])

    def test_approle_preserves_restrictions(self):
        current = {'bind_secret_id': True, 'secret_id_num_uses': 2, 'secret_id_ttl': 60,
                   'secret_id_bound_cidrs': ['127.0.0.0/8'], 'local_secret_ids': True}
        payload = AppRoleAdapter.payload(current, [])
        self.assertNotIn('local_secret_ids', payload)
        for key in current.keys() - {'local_secret_ids'}:
            self.assertEqual(payload[key], current[key])


class ClientTests(unittest.TestCase):




    def test_rest_client_refuses_mount_deletion_before_network_io(self):
        client = Client({'address':'https://vault.example.org','timeout_seconds':1,'validate_tls':True}, 'fixture-token')
        for api in ['sys/mounts/apps', 'sys/auth/ad']:
            with self.assertRaises(ConfigurationError):
                client.request('DELETE', api)
        self.assertEqual(client.requests, [])

    def test_error_redaction_and_no_redirect(self):
        error = VaultHTTPError('POST', 'transport', True)
        self.assertNotIn('secret-value', str(error))
        self.assertTrue(error.uncertain)
        self.assertIsNone(NoRedirect().redirect_request(None, None, 307, '', {}, 'https://untrusted.example'))

    def test_transport_diagnostics_classify_without_exposing_secrets(self):
        secret = 'secret-token-password-response'
        certificate_error = ssl.SSLCertVerificationError(1, secret)
        certificate_error.verify_code = 20
        certificate_error.verify_message = secret
        protocol_error = ssl.SSLError(1, secret)
        protocol_error.reason = 'WRONG_VERSION_NUMBER'
        unknown_tls_error = ssl.SSLError(1, secret)
        unknown_tls_error.reason = secret
        failures = [
            (socket.gaierror(socket.EAI_NONAME, secret), 'dns_resolution_failed', 'DNS'),
            (ConnectionRefusedError(errno.ECONNREFUSED, secret), 'connection_refused', 'listener'),
            (ConnectionResetError(errno.ECONNRESET, secret), 'connection_reset', 'load balancer'),
            (BrokenPipeError(errno.EPIPE, secret), 'connection_closed', 'load balancer'),
            (OSError(errno.ENETUNREACH, secret), 'network_unreachable', 'routes'),
            (OSError(errno.EHOSTUNREACH, secret), 'host_unreachable', 'routing'),
            (socket.timeout(secret), 'timeout', 'timeout_seconds'),
            (PermissionError(errno.EACCES, secret), 'permission_denied', 'execution user'),
            (OSError(errno.EIO, secret), 'os_error', 'logs'),
            (certificate_error, 'tls_certificate_verification_failed', 'verify_code=20'),
            (protocol_error, 'tls_error', 'WRONG_VERSION_NUMBER'),
            (unknown_tls_error, 'tls_error', 'mutual TLS'),
            (URLError(secret), 'transport_error', 'proxies are disabled'),
        ]
        connection = {'address': 'https://vault.example.org', 'timeout_seconds': 7, 'validate_tls': True}
        client = Client(connection, secret)
        for failure, reason, hint in failures:
            # Exercise both direct socket/TLS errors and urllib wrappers without network I/O.
            # RU: Проверяем прямые ошибки сокета/TLS и обёртки urllib без сетевых запросов.
            for wrapped in (failure, URLError(failure)):
                with self.subTest(reason=reason, wrapped=type(wrapped).__name__):
                    client.opener = Mock()
                    client.opener.open.side_effect = wrapped
                    with self.assertRaises(VaultHTTPError) as raised:
                        client.request('GET', 'sys/health')
                    message = str(raised.exception)
                    self.assertIn('status=transport', message)
                    self.assertIn('reason=' + reason, message)
                    self.assertIn(hint, message)
                    self.assertIn('ca_source=python_default_trust_store', message)
                    self.assertIn('tls_validation=enabled', message)
                    self.assertIn('timeout_seconds=7', message)
                    self.assertIn('proxy=disabled', message)
                    self.assertNotIn(secret, message)
                    self.assertFalse(raised.exception.uncertain)
        client.opener.open.side_effect = URLError(certificate_error)
        with self.assertRaises(VaultHTTPError) as raised:
            client.request('POST', 'auth/ldap/config', {'bindpass': secret})
        self.assertTrue(raised.exception.uncertain)
        self.assertIn('reconcile before retry', str(raised.exception))
        self.assertNotIn(secret, str(raised.exception))

    def test_tls_file_diagnostics_identify_stage_and_ca_source(self):
        secret = 'secret-file-path-or-key-password'
        connection = {'address': 'https://vault.example.org', 'timeout_seconds': 7,
                      'validate_tls': True, 'ca_file': '/private/' + secret}
        missing = FileNotFoundError(errno.ENOENT, secret, secret)
        with patch('vault_configuration.client.ssl.create_default_context', side_effect=missing):
            with self.assertRaises(ConfigurationError) as raised:
                Client(connection, secret)
        message = str(raised.exception)
        self.assertIn('stage=load_ca', message)
        self.assertIn('reason=file_not_found', message)
        self.assertIn('ca_source=explicit_ca_file', message)
        self.assertNotIn(secret, message)
        connection.update(client_cert=secret, client_key=secret)
        context = Mock()
        mismatch = ssl.SSLError(1, secret)
        mismatch.reason = 'KEY_VALUES_MISMATCH'
        context.load_cert_chain.side_effect = mismatch
        with patch('vault_configuration.client.ssl.create_default_context', return_value=context):
            with self.assertRaises(ConfigurationError) as raised:
                Client(connection, secret)
        self.assertIn('stage=load_client_certificate', str(raised.exception))
        self.assertIn('KEY_VALUES_MISMATCH', str(raised.exception))
        self.assertNotIn(secret, str(raised.exception))

    def test_http_failures_stay_redacted_and_missing_404_remains_optional(self):
        secret = 'secret-server-response-and-token'
        client = Client({'address': 'https://vault.example.org', 'timeout_seconds': 1,
                         'validate_tls': True}, secret)
        client.opener = Mock()
        for method, status, uncertain in [('GET', 403, False), ('POST', 503, True)]:
            response = io.BytesIO(secret.encode())
            client.opener.open.side_effect = HTTPError('https://' + secret, status, secret, {}, response)
            with self.assertRaises(VaultHTTPError) as raised:
                client.request(method, 'sys/health')
            self.assertEqual(raised.exception.status, status)
            self.assertEqual(raised.exception.uncertain, uncertain)
            self.assertNotIn(secret, str(raised.exception))
            self.assertTrue(response.closed)
        client.opener.open.side_effect = HTTPError('https://' + secret, 404, secret, {}, io.BytesIO())
        self.assertIsNone(client.read('missing', missing=True))


if __name__ == '__main__':
    unittest.main()
