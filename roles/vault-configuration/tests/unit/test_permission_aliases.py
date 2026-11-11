"""Permission aliases preserve safety, ACL meaning and the matrix alphabet."""
import copy
import csv
import io
import unittest

from test_core import config, user, grant
from vault_configuration.common import ConfigurationError
from vault_configuration.compiler import (PERMISSIONS, PERMISSION_ALIASES, expand_permissions,
                                           compile_grant, compile_personal, reverse)
from vault_configuration.validation import validate
from vault_configuration.runner import run


class PermissionAliasTests(unittest.TestCase):
    def settings(self, destructive=False):
        settings = config()
        settings['safety'] = {'allow_destructive_grants': destructive}
        return settings

    def test_aliases_and_scalar_operation_expand_to_canonical_lists(self):
        self.assertEqual(set(expand_permissions('all')), set(PERMISSIONS))
        self.assertEqual(expand_permissions('read'), ['read'])
        for alias, expected in PERMISSION_ALIASES.items():
            self.assertEqual(expand_permissions(alias), sorted(expected))
            self.assertEqual(expand_permissions([alias]), sorted(expected))

    def test_mixed_aliases_and_permissions_deduplicate_overlapping_operations(self):
        self.assertEqual(expand_permissions(['read_only', 'write', 'read']),
                         ['list', 'read', 'read_metadata', 'write'])
        self.assertEqual(expand_permissions(['all', 'read_write']), sorted(PERMISSIONS))
        for value in ([], '', ['unknown'], ['all', 'all'], ['read', 'read'], None, True, {'all': True}, [False]):
            with self.subTest(value=value):
                with self.assertRaises(ConfigurationError): expand_permissions(value)

    def test_read_write_does_not_include_any_delete_operation(self):
        expanded = expand_permissions('read_write')
        self.assertEqual(set(expanded), {'list', 'read', 'write', 'patch', 'read_metadata', 'update_metadata'})
        self.assertFalse(set(expanded) & {'delete_latest', 'delete_versions', 'undelete_versions', 'destroy_versions', 'delete_metadata'})

    def test_grants_normalize_without_mutating_inventory_and_preserve_safety_checks(self):
        declarations = {'users': [user()], 'grants': [grant('all')]}
        before = copy.deepcopy(declarations)
        with self.assertRaisesRegex(ConfigurationError, 'Destructive grants'):
            validate(self.settings(), declarations, {})
        _, normalized = validate(self.settings(True), declarations, {})
        self.assertEqual(normalized['grants'][0]['paths'][0]['permissions'], sorted(PERMISSIONS))
        self.assertEqual(declarations, before)
        for alias in ('all', 'read_only', 'read_write'):
            with self.subTest(alias=alias):
                with self.assertRaisesRegex(ConfigurationError, 'exact.*list'):
                    validate(self.settings(True), {'users': [user()], 'grants': [grant(alias, scope='exact')]}, {})

    def test_personal_aliases_preserve_destructive_guard(self):
        personal = {'enabled': True, 'mount': 'users', 'permissions': 'all',
                    'subjects': [{'kind': 'user', 'id': 'alice'}]}
        declarations = {'users': [user()], 'personal_access': personal}
        with self.assertRaisesRegex(ConfigurationError, 'Destructive grants'):
            validate(self.settings(), declarations, {})
        _, normalized = validate(self.settings(True), declarations, {})
        self.assertEqual(normalized['personal_access']['permissions'], sorted(PERMISSIONS))
        self.assertEqual(compile_personal(personal), compile_personal(normalized['personal_access']))

    def test_alias_and_explicit_lists_compile_identically_and_export_explicitly(self):
        for alias, operations in PERMISSION_ALIASES.items():
            with self.subTest(alias=alias):
                text = compile_grant(grant(alias))
                self.assertEqual(text, compile_grant(grant(list(operations))))
                decoded = reverse(text, ['apps'])
                self.assertEqual(decoded['paths'][0]['permissions'], sorted(operations))
                self.assertIsInstance(decoded['paths'][0]['permissions'], list)

    def test_inventory_matrix_keeps_eleven_positions(self):
        for alias, expected in [('all', 'LRWPMUDVNXZ'), ('read_only', 'LR..M......'), ('read_write', 'LRWPMU.....')]:
            with self.subTest(alias=alias):
                settings = dict(self.settings(True), mode='matrix')
                report = run(settings, {'users': [user()], 'grants': [grant(alias)]}, '', matrix={'source': 'inventory'})
                rows = list(csv.DictReader(io.StringIO(report['_matrix_csv']), delimiter=';'))
                row = next(row for row in rows if row['mount'] == 'apps' and row['path'] == 'payments/prod/*')
                self.assertEqual(row['u:alice'], expected)
