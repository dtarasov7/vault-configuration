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
from vault_configuration.planner import Planner, merged_links, resolve
from vault_configuration.adapters import KubernetesAdapter, JWTAdapter, AppRoleAdapter
from vault_configuration.state import StateStore, atomic_write
from vault_configuration.client import Client, NoRedirect, VaultHTTPError
from vault_configuration.runner import summaries, run


def config(directory='/test'):
    return {'connection': {'address': 'https://vault.example.org'},
            'management': {'owner': 'test', 'policy_prefix': 'vam-test-', 'state_file': directory + '/state.json'}}


def grant(permissions=None, logical='payments/prod', scope='subtree'):
    return {'id': 'access', 'subjects': [{'kind': 'user', 'id': 'alice'}],
            'paths': [{'mount': 'apps', 'path': logical, 'scope': scope, 'permissions': permissions or ['read']}]}


def user():
    return {'id': 'alice', 'name': 'alice', 'source': 'external'}


def view():
    return {'cluster_id': 'cluster', 'version': '2.0.0', 'mounts': {name + '/': {'type':'kv','options':{'version':'2'}} for name in ['certs','infra','apps','cicd','users']}, 'auth': {}, 'objects': {},
            'entities': {}, 'groups': {}, 'policies': {}, 'aliases': {}, 'userpass': {}, 'roles': {}, 'automation_entity': ''}


def state():
    return {'schema_version': 1, 'cluster_id': 'cluster', 'owner': 'test', 'resources': {}, 'journal': [], 'pending': None}


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
        self.invalid({'users': []}, lambda value: value['management'].update(prune=True))

    def test_duplicate_bindings_members_and_subjects(self):
        first = dict(user(), source='userpass', auth_mount='userpass', login='alice', password_revision='r1')
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
        self.invalid({'ldap':[copy.deepcopy(base)]})
        base['bind_password_revision'] = 'r1'
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


class PlannerTests(unittest.TestCase):
    def build(self, sections, configuration=None, current=None, registry=None):
        conf, normalized = validate(configuration or config(), sections, {})
        planner = Planner(conf, normalized, current or view(), registry or state())
        return planner, planner.build()

    def test_plan_deterministic_and_public(self):
        sections = {'users': [user()], 'grants': [grant()]}
        _, first = self.build(sections)
        _, second = self.build(sections)
        self.assertEqual(first, second)
        self.assertEqual(summaries(first)['Планируем добавить']['count'], 2)
        self.assertEqual(set(public({'password': 'secret', 'password_revision': 'r1'})), {'password_revision'})

    def test_adoption_owner_and_protected(self):
        current = view()
        entry = {'uuid': 'uuid', 'path': 'identity/entity/id/uuid', 'data': {'name': 'alice', 'metadata': {}, 'policies': [], 'disabled': False}}
        current['entities']['uuid'] = entry
        current['objects'][entry['path']] = entry['data']
        with self.assertRaises(ConfigurationError):
            self.build({'users': [user()]}, current=current)
        configuration = config()
        configuration['management']['adoption'] = [{'kind': 'entity', 'id': 'alice', 'uuid': 'uuid'}]
        self.build({'users': [user()]}, configuration, current)
        entry['data']['metadata']['vam_owner'] = 'other'
        with self.assertRaises(ConfigurationError):
            self.build({'users': [user()]}, configuration, current)
        entry['data']['metadata'] = {}
        configuration['safety'] = {'protected_entities': ['uuid']}
        with self.assertRaises(ConfigurationError):
            self.build({'users': [user()]}, configuration, current)

    def test_preserve_foreign_links(self):
        self.assertEqual(merged_links(['foreign', 'owned-old'], ['owned-old'], ['owned-new']), ['foreign', 'owned-new'])

    def test_prune_limit_and_omitted_grants(self):
        current, registry, configuration = view(), state(), config()
        policy = {'policy': compile_grant(grant())}
        api = 'sys/policies/acl/vam-test-old'
        current['objects'][api] = policy
        current['policies']['vam-test-old'] = {'path':api, 'data':policy}
        registry['resources']['policy:old'] = {'kind':'policy','id':'old','path':api,'uuid':'','links':{},
                                                'hash':digest(policy),'section':'grants'}
        configuration['management'].update(prune=True, deletion_approvals=[{'kind':'policy','id':'old','hash':digest(policy),'dependencies_cleared':True}])
        configuration['safety'] = {'allow_empty_desired':True,'max_deletions':0}
        with self.assertRaises(ConfigurationError):
            self.build({'grants':[]}, configuration, current, registry)
        _, plan = self.build({}, configuration, current, registry)
        self.assertEqual(plan['operations'], [])
        configuration['safety']['max_deletions'] = 1
        _, plan = self.build({'grants':[]}, configuration, current, registry)
        self.assertEqual(plan['operations'][0]['action'], 'delete')

    def test_digest_never_hashes_password(self):
        current = view()
        current['auth']['userpass/'] = {'accessor':'accessor', 'type':'userpass'}
        local = dict(user(), source='userpass',auth_mount='userpass',login='alice',password_revision='r1',password='first-secret')
        _, first = self.build({'users':[local]}, current=current)
        local['password'] = 'different-secret'
        _, second = self.build({'users':[local]}, current=current)
        self.assertEqual(first['digest'], second['digest'])
        self.assertNotIn('different-secret', json.dumps(second))

    def test_peer_owner_cannot_claim_the_same_role_policy_link(self):
        current = view()
        current['auth']['kubernetes/'] = {'type':'kubernetes','accessor':'accessor'}
        api = 'auth/kubernetes/role/backend'
        data = {'bound_service_account_names':['backend'],'bound_service_account_namespaces':['prod'], 'token_policies':['foreign']}
        current['roles']['kubernetes/backend'] = {'path':api,'data':data,'type':'kubernetes','mount':'kubernetes','name':'backend'}
        current['objects'][api] = data
        current['policies']['foreign'] = {'path':'sys/policies/acl/foreign','data':{'policy':compile_grant(grant())}}
        peer = state()
        peer['owner'] = 'other'
        peer['resources']['auth_role:backend'] = {'kind':'auth_role','id':'backend','path':api,'uuid':'',
            'hash':digest(data),'links':{'policies':['foreign']},'section':'auth_roles','shared':True}
        sections = {'auth_roles':[{'id':'backend','type':'kubernetes','auth_mount':'kubernetes','name':'backend'}],
                    'grants':[{'id':'external','subjects':[{'kind':'auth_role','id':'backend'}], 'existing_policies':['foreign']}]}
        configuration, sections = validate(config(), sections, {})
        with self.assertRaises(ConfigurationError):
            Planner(configuration, sections, current, state(), [peer]).build()

    def test_policy_prefix_and_login_migrations_do_not_orphan_objects(self):
        registry, current, configuration = state(), view(), config()
        api = 'sys/policies/acl/' + policy_name('vam-test-', 'access')
        policy = {'policy':compile_grant(grant())}
        registry['resources']['policy:access'] = {'kind':'policy','id':'access','uuid':'','path':api,
            'links':{},'hash':digest(policy),'section':'grants'}
        current['policies'][api.rsplit('/',1)[-1]] = {'path':api,'data':policy}
        current['objects'][api] = policy
        configuration['management']['policy_prefix'] = 'vam-new-'
        with self.assertRaises(ConfigurationError):
            self.build({'users':[user()], 'grants':[grant()]}, configuration, current, registry)
        registry = state()
        registry['resources']['userpass:alice'] = {'kind':'userpass','id':'alice','uuid':'',
            'path':'auth/userpass/users/alice','links':{},'hash':'hash','section':'users','accessor':'accessor'}
        current['auth']['userpass/'] = {'accessor':'accessor','type':'userpass'}
        local = dict(user(), source='userpass',auth_mount='userpass',login='new-login',password_revision='r1',password='test-secret')
        with self.assertRaises(ConfigurationError):
            self.build({'users':[local]}, config(), current, registry)

    def test_missing_mount_is_planned_and_never_pruned(self):
        current = view()
        current['mounts'].pop('apps/')
        _, plan = self.build({}, current=current)
        self.assertEqual([(operation['kind'], operation['action']) for operation in plan['operations']], [('mount', 'create')])
        configuration = config()
        configuration['mounts'] = []
        configuration['management'].update(prune=True, prune_identities=True)
        registry = state()
        registry['resources']['mount:apps'] = {'kind':'mount','id':'apps','path':'sys/mounts/apps','uuid':'',
            'links':{},'hash':'hash','section':'mounts'}
        _, plan = self.build({}, configuration, current, registry)
        self.assertEqual(plan['operations'], [])

    def test_missing_password_before_writes(self):
        current = view()
        current['auth']['userpass/'] = {'accessor': 'auth-id', 'type': 'userpass'}
        local = dict(user(), source='userpass', auth_mount='userpass', login='alice', password_revision='r1')
        with self.assertRaises(ConfigurationError):
            self.build({'users': [local]}, current=current)

    def test_ldap_personal_uses_new_mount_accessor_and_requires_username_aliases(self):
        personal = {'enabled': True, 'identity_source': 'ldap_login', 'auth_mount': 'ldap',
                    'mount': 'users', 'path_prefix': 'dep1', 'permissions': ['read', 'write', 'list'],
                    'subjects': [{'kind': 'group', 'id': 'department'}]}
        sections = {'groups': [{'id': 'department', 'name': 'department', 'type': 'external',
                                'alias': {'auth_mount': 'ldap', 'name': 'dep1'}}],
                    'ldap': [{'id': 'directory', 'auth_mount': 'ldap', 'allow_insecure_ldap': True,
                              'config': {'url': 'ldap://localhost:389', 'userdn': 'ou=people,dc=test',
                                         'groupdn': 'ou=groups,dc=test'}}],
                    'personal_access': personal}
        planner, plan = self.build(sections)
        policy = planner.models['policy:personal']['payload']
        resolved = resolve(policy, {'auth_mount:ldap': 'auth_ldap_new'})
        self.assertEqual(resolved['policy'], compile_personal(personal, 'auth_ldap_new'))
        create_order = [operation['key'] for operation in plan['operations']]
        self.assertLess(create_order.index('auth_mount:ldap'), create_order.index('policy:personal'))
        sections['ldap'][0]['config']['username_as_alias'] = False
        with self.assertRaisesRegex(ConfigurationError, 'username_as_alias'):
            self.build(sections)
        sections['ldap'] = None
        current = view()
        current['auth']['ldap/'] = {'type': 'ldap', 'accessor': 'auth_ldap_new'}
        current['objects']['auth/ldap/config'] = {'username_as_alias': True}
        registry = state()
        registry['resources']['policy:personal'] = {'accessor': 'auth_ldap_old', 'auth_mount': 'ldap'}
        with self.assertRaisesRegex(ConfigurationError, 'accessor changed'):
            self.build(sections, current=current, registry=registry)

    def test_ldap_personal_rejects_invalid_sources_fields_and_subjects(self):
        group = {'id': 'department', 'name': 'department', 'type': 'internal'}
        personal = {'enabled': True, 'identity_source': 'ldap_login', 'auth_mount': 'ldap',
                    'mount': 'users', 'path_prefix': 'dep1', 'permissions': ['read'],
                    'subjects': [{'kind': 'group', 'id': 'department'}]}
        validate(config(), {'groups': [group], 'personal_access': personal}, {})
        invalid = [dict(personal, identity_source='other'), dict(personal, identity_source='entity_id'),
                   dict(personal, path_prefix='../other'),
                   dict(personal, subjects=[{'kind': 'auth_role', 'id': 'automation'}])]
        missing_mount = dict(personal)
        missing_mount.pop('auth_mount')
        invalid.append(missing_mount)
        for item in invalid:
            with self.subTest(personal=item), self.assertRaises(ConfigurationError):
                validate(config(), {'groups': [group], 'personal_access': item}, {})

    def test_personal_external_group_uuid_preserves_server_managed_membership(self):
        current = view()
        current['auth']['ldap/'] = {'type': 'ldap', 'accessor': 'auth_ldap_test'}
        current['objects']['auth/ldap/config'] = {'username_as_alias': True}
        uuid = '00000000-0000-4000-8000-000000000001'
        data = {'name': 'existing', 'type': 'external', 'metadata': {'origin': 'directory'},
                'policies': [], 'member_entity_ids': ['existing-user'], 'member_group_ids': []}
        entry = {'uuid': uuid, 'path': 'identity/group/id/' + uuid, 'data': data}
        current['groups'][uuid] = entry
        current['objects'][entry['path']] = data
        personal = {'enabled': True, 'identity_source': 'ldap_login', 'auth_mount': 'ldap',
                    'mount': 'users', 'permissions': ['read'],
                    'subjects': [{'kind': 'group', 'uuid': uuid}]}
        planner, _ = self.build({'personal_access': personal}, current=current)
        payload = planner.models['group:uuid-' + uuid]['payload']
        self.assertNotIn('member_entity_ids', payload)
        self.assertNotIn('member_group_ids', payload)
        self.assertEqual(payload['metadata'], {'origin': 'directory'})
        self.assertEqual(current['groups'][uuid]['data']['member_entity_ids'], ['existing-user'])

    def test_missing_userpass_mount_is_created_once_before_users_and_aliases(self):
        alice = dict(user(), source='userpass', auth_mount='staff/local', login='alice',
                     password_revision='r1', password='fixture-alice')
        bob = dict(alice, id='bob', name='bob', login='bob', password='fixture-bob')
        planner, plan = self.build({'users': [alice, bob]})
        mounts = [operation for operation in plan['operations'] if operation['kind'] == 'auth_mount']
        self.assertEqual([(operation['path'], operation['action']) for operation in mounts],
                         [('sys/auth/staff/local', 'create')])
        self.assertEqual(plan['operations'][0]['kind'], 'auth_mount')
        for identifier in ['alice', 'bob']:
            model = planner.models['userpass:' + identifier]
            self.assertEqual(model['accessor'], {'$ref': 'auth_mount:staff/local'})

    def test_userpass_mount_type_overlap_and_accessor_conflicts_fail_before_apply(self):
        local = dict(user(), source='userpass', auth_mount='staff/local', login='alice',
                     password_revision='r1', password='fixture')
        for mount, kind in [('staff/local/', 'ldap'), ('staff/', 'userpass'),
                            ('staff/local/child/', 'userpass')]:
            with self.subTest(mount=mount, kind=kind):
                current = view()
                current['auth'][mount] = {'type': kind, 'accessor': 'existing'}
                with self.assertRaises(ConfigurationError):
                    self.build({'users': [local]}, current=current)
        current = view()
        current['auth']['staff/local/'] = {'type': 'userpass', 'accessor': 'replacement'}
        registry = state()
        registry['resources']['auth_mount:staff/local'] = {
            'kind': 'auth_mount', 'id': 'staff/local', 'path': 'sys/auth/staff/local',
            'uuid': 'original', 'links': {}, 'hash': 'hash', 'section': 'users'}
        with self.assertRaises(ConfigurationError):
            self.build({'users': [local]}, current=current, registry=registry)

    def test_userpass_auth_mount_is_not_pruned_when_users_are_empty(self):
        configuration = config()
        configuration['management'].update(prune=True, prune_identities=True)
        configuration['safety'] = {'allow_empty_desired': True}
        current = view()
        current['auth']['userpass/'] = {'type': 'userpass', 'accessor': 'auth-id'}
        current['objects']['sys/auth/userpass'] = {'type': 'userpass'}
        registry = state()
        registry['resources']['auth_mount:userpass'] = {
            'kind': 'auth_mount', 'id': 'userpass', 'path': 'sys/auth/userpass',
            'uuid': 'auth-id', 'links': {}, 'hash': 'hash', 'section': 'users'}
        _, plan = self.build({'users': []}, configuration, current, registry)
        self.assertEqual(plan['operations'], [])


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


class StateAndClientTests(unittest.TestCase):
    def test_yaml_dependency_is_checked_before_any_api_request(self):
        for mode in ['dry', 'export']:
            with self.subTest(mode=mode):
                configuration = config()
                configuration.update(mode=mode, report_destination='/test/plan.yml')
                with patch('vault_configuration.runner.yaml', None), patch('vault_configuration.runner.Client') as client:
                    with self.assertRaisesRegex(ConfigurationError, 'PyYAML is required'):
                        run(configuration, {}, 'fixture-token')
                    client.assert_not_called()

    def test_atomic_permissions_backup_and_identity(self):
        with tempfile.TemporaryDirectory(dir=str(ROLE.parents[1] / '.work')) as directory:
            filename = directory + '/state.json'
            store = StateStore(filename, 'test')
            initial = store.load('cluster')
            self.assertFalse(os.path.exists(filename))
            store.save(initial)
            self.assertEqual(stat.S_IMODE(os.stat(filename).st_mode), 0o600)
            initial['journal'].append({'action': 'test'})
            store.save(initial)
            self.assertTrue(os.path.exists(filename + '.bak'))
            with self.assertRaises(ConfigurationError):
                store.load('different-cluster')
            with open(filename, 'w') as stream:
                stream.write('broken')
            with self.assertRaises(ConfigurationError):
                store.load('cluster')

    def test_check_file_does_not_create_and_symlink_rejected(self):
        with tempfile.TemporaryDirectory(dir=str(ROLE.parents[1] / '.work')) as directory:
            filename = directory + '/nested/report.json'
            self.assertTrue(atomic_write(filename, '{}', check_mode=True))
            self.assertFalse(os.path.exists(directory + '/nested'))
            target = directory + '/target'
            atomic_write(target, '{}')
            os.symlink(target, directory + '/link')
            with self.assertRaises(ConfigurationError):
                atomic_write(directory + '/link', '{}')

    def test_directory_lock_serializes_different_owners(self):
        with tempfile.TemporaryDirectory(dir=str(ROLE.parents[1] / '.work')) as directory:
            first = StateStore(directory + '/one.json', 'one')
            second = StateStore(directory + '/two.json', 'two')
            first.acquire()
            try:
                with self.assertRaises(ConfigurationError):
                    second.acquire()
            finally:
                first.close()
                second.close()

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
