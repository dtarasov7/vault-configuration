"""Strict inventory validation, before any network write or local state creation."""
import copy
import ipaddress
import unicodedata
import re
from urllib.parse import urlsplit

from .common import check, merge, digest
from .compiler import path, PERMISSIONS, SEGMENT

DEFAULTS = {
    'mode': 'dry',
    'connection': {'validate_tls': True, 'timeout_seconds': 30, 'allow_insecure_http': False},
    'mounts': ['certs', 'infra', 'apps', 'cicd', 'users'],
    'management': {'adoption': []},
    'safety': {'allow_mount_root': False,
               'allow_destructive_grants': False, 'protected_policies': ['root', 'default'],
               'protected_entities': [], 'protected_groups': []},
}
TOKEN_FIELDS = {
    'token_ttl': int, 'token_max_ttl': int, 'token_explicit_max_ttl': int,
    'token_period': int, 'token_num_uses': int, 'token_no_default_policy': bool,
    'token_type': str, 'token_bound_cidrs': list,
}


def fields(value, allowed, required, location):
    check(isinstance(value, dict), location + ' must be a mapping')
    check(not set(value) - set(allowed), location + ': unknown fields')
    check(set(required) <= set(value), location + ': missing required fields')


def typed(value, kind, location):
    check(type(value) is kind, location + ': invalid type')


def name(value, location):
    check(isinstance(value, str) and bool(SEGMENT.fullmatch(value)), location + ': invalid name/id')


def strings(values, location):
    typed(values, list, location)
    check(all(isinstance(value, str) and value for value in values), location + ': expected strings')
    check(len(values) == len(set(values)), location + ': duplicates')


def choices(value, allowed, location):
    check(value in allowed, location + ': unsupported value')


def alias(value):
    fields(value, ['auth_mount', 'name'], ['auth_mount', 'name'], 'alias')
    path(value['auth_mount'])
    check(isinstance(value['name'], str) and value['name'] and
          all(unicodedata.category(char) not in {'Cc', 'Cs'} for char in value['name']), 'Invalid alias name')


def subject(value):
    fields(value, ['kind', 'id', 'uuid'], ['kind'], 'subject')
    choices(value['kind'], ['user', 'group', 'auth_role'], 'subject.kind')
    check(('id' in value) != ('uuid' in value), 'Subject needs exactly one id or uuid')
    if 'id' in value:
        name(value['id'], 'subject.id')
    else:
        check(value['kind'] != 'auth_role' and
              isinstance(value['uuid'], str) and bool(re.fullmatch(r'[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}', value['uuid'])),
              'Invalid external UUID subject')


def permissions(value, safety):
    strings(value, 'permissions')
    check(bool(value) and set(value) <= set(PERMISSIONS), 'Unknown or empty permissions')
    check(safety['allow_destructive_grants'] or
          not set(value) & {'destroy_versions', 'delete_metadata'},
          'Destructive grants need allow_destructive_grants')


def unique(items, location):
    check(len(items) == len({digest(item) for item in items}), location + ': duplicates')


def validate(config, sections, export):
    """Normalize defaults and validate the full configuration contract.
    RU: Применить значения по умолчанию и проверить контракт конфигурации.

    Args:
        config (dict): Role configuration / настройки роли.
        sections (dict): Desired sections; None leaves a section unmanaged / желаемые разделы; None исключает управление разделом.
        export (dict | None): Export options / параметры экспорта.

    Returns:
        tuple[dict, dict]: Normalized config and sections / нормализованные настройки и разделы.

    Raises:
        ConfigurationError: Invalid types, references, safety settings or cycles / неверные типы, ссылки, защитные настройки или циклы.
    """
    fields(config, list(DEFAULTS) + ['expected_plan_digest'], [], 'config')
    for key in ('connection', 'management', 'safety'):
        allowed = set(DEFAULTS[key])
        required = []
        if key == 'connection':
            allowed |= {'address', 'ca_file', 'client_cert', 'client_key'}
            required = ['address']
        if key == 'management':
            allowed |= {'owner', 'policy_prefix'}
            required = ['owner', 'policy_prefix']
        fields(config.get(key, {}), allowed, required, key)
    result = merge(DEFAULTS, config)
    choices(result['mode'], ['apply', 'dry', 'export', 'matrix'], 'mode')
    connection = result['connection']
    for key in ('validate_tls', 'allow_insecure_http'):
        typed(connection[key], bool, key)
    typed(connection['timeout_seconds'], int, 'timeout_seconds')
    check(0 < connection['timeout_seconds'] <= 600, 'timeout_seconds out of range')
    check(isinstance(connection['address'], str), 'address must be a string')
    address = urlsplit(connection['address'])
    check(address.scheme in {'https', 'http'} and address.hostname and not address.username and
          not address.password and address.path in {'', '/'} and not address.query and not address.fragment,
          'address must be an HTTP(S) origin without credentials or URL paths')
    check(address.scheme == 'https' or connection['allow_insecure_http'], 'HTTPS is required by default')
    for key in ('ca_file', 'client_cert', 'client_key'):
        if key in connection:
            check(isinstance(connection[key], str) and connection[key], key + ' must be a file path')
    check(('client_key' in connection) == ('client_cert' in connection), 'Specify both client cert and key')
    strings(result['mounts'], 'mounts')
    for mount in result['mounts']:
        path(mount)
        check(not any(other != mount and (mount.startswith(other + '/') or other.startswith(mount + '/')) for other in result['mounts']),
              'Selected mounts must not overlap')
    management = result['management']
    name(management['owner'], 'owner')
    name(management['policy_prefix'], 'policy_prefix')
    for key, value in result['safety'].items():
        typed(value, list if key.startswith('protected_') else bool, key)
        if key.startswith('protected_'):
            strings(value, key)
    for key in ('adoption',):
        typed(management[key], list, key)
        seen = set()
        for entry in management[key]:
            allowed = ['kind', 'id', 'uuid', 'hash']
            fields(entry, allowed, ['kind', 'id'], key)
            choices(entry['kind'], ['entity', 'group', 'policy', 'userpass', 'auth_role', 'entity_alias', 'group_alias', 'ldap_config'], key)
            check((entry['kind'], entry['id']) not in seen, key + ': duplicates')
            seen.add((entry['kind'], entry['id']))
            check(('hash' in entry) != ('uuid' in entry), 'Adoption requires exactly one expected uuid or hash')
    for key in ('expected_plan_digest',):
        if key in result:
            check(isinstance(result[key], str) and result[key], 'Invalid ' + key)
    normalized = copy.deepcopy(sections)
    indices = {}
    for section in ('users', 'groups', 'grants', 'auth_roles'):
        items = normalized.get(section)
        if items is None:
            continue
        typed(items, list, section)
        indices[section] = {}
        seen_names = set()
        for item in items:
            check(isinstance(item, dict) and 'id' in item, section + ': missing id')
            name(item['id'], section + '.id')
            check(item['id'] not in indices[section], section + ': duplicate id')
            indices[section][item['id']] = item
            if section == 'users':
                fields(item, ['id', 'name', 'source', 'auth_mount', 'login', 'password',
                              'password_policy', 'disabled', 'aliases', 'token_parameters'],
                       ['id', 'name', 'source'], section)
                name(item['name'], 'user.name')
                choices(item['source'], ['userpass', 'external'], 'source')
                typed(item.setdefault('disabled', False), bool, 'disabled')
                typed(item.setdefault('aliases', []), list, 'aliases')
                for entry in item['aliases']:
                    alias(entry)
                if item['source'] == 'userpass':
                    check({'auth_mount', 'login'} <= set(item), 'userpass missing login/mount')
                    path(item['auth_mount'])
                    name(item['login'], 'login')
                    check(item['login'] == item['login'].lower() and not item['login'].startswith('-') and
                          not item['login'].endswith('.'), 'Invalid lowercase userpass login')
                    choices(item.setdefault('password_policy', 'on_create'), ['on_create', 'always'], 'password_policy')
                    if 'password' in item:
                        typed(item['password'], str, 'password')
                    params = item.setdefault('token_parameters', {})
                    fields(params, TOKEN_FIELDS, [], 'token_parameters')
                    for key, value in params.items():
                        typed(value, TOKEN_FIELDS[key], key)
                        if type(value) is int:
                            check(value >= 0, key + ' must be nonnegative')
                    if 'token_type' in params:
                        choices(params['token_type'], ['service', 'batch', 'default'], 'token_type')
                    if 'token_bound_cidrs' in params:
                        strings(params['token_bound_cidrs'], 'token_bound_cidrs')
                        networks = []
                        for cidr in params['token_bound_cidrs']:
                            try:
                                network = ipaddress.ip_network(cidr, strict=False)
                            except ValueError:
                                check(False, 'Invalid token_bound_cidrs network')
                            networks.append(str(network))
                        params['token_bound_cidrs'] = sorted(set(networks))
                else:
                    check(not set(item) & {'auth_mount', 'login', 'password', 'password_revision', 'password_policy', 'token_parameters'},
                          'External identity cannot contain userpass fields')
            elif section == 'groups':
                fields(item, ['id', 'name', 'type', 'members', 'member_groups', 'alias'], ['id', 'name', 'type'], section)
                name(item['name'], 'group.name')
                choices(item['type'], ['internal', 'external'], 'group.type')
                if item['type'] == 'external':
                    check(not set(item) & {'members', 'member_groups'}, 'External groups cannot have inventory members')
                else:
                    check('alias' not in item, 'Only external groups can have a group alias')
                    for key in ('members', 'member_groups'):
                        typed(item.setdefault(key, []), list, key)
                        for member in item[key]:
                            if isinstance(member, str):
                                name(member, key)
                            else:
                                subject(dict(member, kind='user' if key == 'members' else 'group'))
                                check(set(member) == {'uuid'}, 'External member requires uuid')
                if 'alias' in item:
                    alias(item['alias'])
            elif section == 'auth_roles':
                fields(item, ['id', 'type', 'auth_mount', 'name'], ['id', 'type', 'auth_mount', 'name'], section)
                choices(item['type'], ['kubernetes', 'jwt', 'oidc', 'approle'], 'auth role type')
                path(item['auth_mount'])
                name(item['name'], 'auth role name')
            else:
                fields(item, ['id', 'subjects', 'paths', 'existing_policies', 'discovery_paths'], ['id', 'subjects'], section)
                typed(item['subjects'], list, 'subjects')
                check(bool(item['subjects']), 'Grant needs subjects')
                for entry in item['subjects']:
                    subject(entry)
                check(('paths' in item) != ('existing_policies' in item), 'Grant needs paths XOR existing_policies')
                if 'existing_policies' in item:
                    strings(item['existing_policies'], 'existing_policies')
                    check(bool(item['existing_policies']) and 'discovery_paths' not in item, 'Invalid existing policy grant')
                    for policy in item['existing_policies']:
                        name(policy, 'policy name')
                    check(not set(item['existing_policies']) & set(result['safety']['protected_policies'] + ['root', 'default']),
                          'Protected policy assignment is prohibited')
                else:
                    typed(item['paths'], list, 'paths')
                    check(bool(item['paths']), 'paths cannot be empty')
                    for entry in item['paths']:
                        fields(entry, ['mount', 'path', 'scope', 'permissions'], ['mount', 'path', 'scope', 'permissions'], 'grant path')
                        check(entry['mount'] in result['mounts'], 'Grant mount is not selected')
                        path(entry['path'], root=result['safety']['allow_mount_root'])
                        choices(entry['scope'], ['exact', 'subtree'], 'scope')
                        permissions(entry['permissions'], result['safety'])
                        check('list' not in entry['permissions'] or entry['scope'] == 'subtree', 'exact + list is ambiguous')
                        check(entry['path'] or entry['scope'] == 'subtree', 'Mount root requires subtree')
                    typed(item.setdefault('discovery_paths', []), list, 'discovery_paths')
                    for entry in item['discovery_paths']:
                        fields(entry, ['mount', 'path'], ['mount', 'path'], 'discovery path')
                        check(entry['mount'] in result['mounts'], 'Discovery mount is not selected')
                        path(entry['path'], root=result['safety']['allow_mount_root'])
            if 'name' in item:
                name_key = (item.get('auth_mount', ''), item['name'])
                check(name_key not in seen_names, section + ': duplicate names')
                seen_names.add(name_key)
    alias_bindings = set()
    accounts = set()
    for item in normalized.get('users') or []:
        aliases = list(item['aliases'])
        if item['source'] == 'userpass':
            binding = (item['auth_mount'], item['login'])
            check(binding not in accounts, 'Duplicate userpass account')
            accounts.add(binding)
            aliases.append({'auth_mount': item['auth_mount'], 'name': item['login']})
        for entry in aliases:
            binding = (entry['auth_mount'], entry['name'])
            check(binding not in alias_bindings, 'Duplicate entity alias binding')
            alias_bindings.add(binding)
    group_aliases = set()
    for item in normalized.get('groups') or []:
        if 'alias' in item:
            binding = (item['alias']['auth_mount'], item['alias']['name'])
            check(binding not in group_aliases, 'Duplicate group alias binding')
            group_aliases.add(binding)
        for field in ('members', 'member_groups'):
            unique(item.get(field, []), field)
    for item in normalized.get('grants') or []:
        for field in ('subjects', 'paths', 'discovery_paths'):
            unique(item.get(field, []), field)
    for group in normalized.get('groups') or []:
        for key, section in [('members', 'users'), ('member_groups', 'groups')]:
            for member in group.get(key, []):
                if isinstance(member, str):
                    check(member in indices.get(section, {}), 'Unknown group member reference')
    def visit(identifier, active, done):
        check(identifier not in active, 'Group membership cycle')
        if identifier in done:
            return
        active.add(identifier)
        for child in indices.get('groups', {}).get(identifier, {}).get('member_groups', []):
            if isinstance(child, str):
                visit(child, active, done)
        active.remove(identifier)
        done.add(identifier)
    done = set()
    for identifier in indices.get('groups', {}):
        visit(identifier, set(), done)
    personal = normalized.get('personal_access')
    if personal is not None:
        fields(personal, ['enabled', 'mount', 'subjects', 'permissions', 'identity_source', 'auth_mount', 'path_prefix'],
               ['enabled'], 'personal_access')
        typed(personal['enabled'], bool, 'personal.enabled')
        if personal['enabled']:
            check({'mount', 'subjects', 'permissions'} <= set(personal), 'Incomplete personal_access')
            check(personal['mount'] in result['mounts'], 'Personal mount is not selected')
            source = personal.setdefault('identity_source', 'entity_id')
            choices(source, ['entity_id', 'ldap_login'], 'personal.identity_source')
            if source == 'ldap_login':
                check('auth_mount' in personal, 'LDAP personal access requires auth_mount')
                path(personal['auth_mount'])
                path(personal.setdefault('path_prefix', ''), root=True)
            else:
                check(not {'auth_mount', 'path_prefix'} & set(personal),
                      'auth_mount/path_prefix require personal identity_source=ldap_login')
            permissions(personal['permissions'], result['safety'])
            typed(personal['subjects'], list, 'personal subjects')
            check(bool(personal['subjects']), 'Personal access needs subjects')
            unique(personal['subjects'], 'personal subjects')
            for entry in personal['subjects']:
                subject(entry)
                allowed = {'user', 'group'} if source == 'ldap_login' else {'user'}
                check(entry['kind'] in allowed, 'Personal subjects must be users, or groups for ldap_login')
    subjects = [entry for grant in normalized.get('grants') or [] for entry in grant['subjects']]
    subjects += (personal or {}).get('subjects', [])
    for entry in subjects:
        if 'id' in entry:
            section = {'user': 'users', 'group': 'groups', 'auth_role': 'auth_roles'}[entry['kind']]
            check(entry['id'] in indices.get(section, {}), 'Unknown subject reference')
    from .ldap import validate_ldap
    validate_ldap(normalized.get('ldap'))
    validate_export(export)
    return result, normalized


def validate_export(export):
    """Validate export scope, filters and output options.
    RU: Проверить область, фильтры и параметры вывода экспорта.

    Args:
        export (dict): Export options / параметры экспорта.

    Returns:
        None.

    Raises:
        ConfigurationError: Unsupported or malformed options / неподдерживаемые или неверные параметры.
    """
    fields(export, ['destination', 'audit_destination', 'scope', 'allow_partial', 'mounts', 'auth_mounts',
                    'entities', 'groups', 'policies', 'auth_roles', 'users', 'ldap'], [], 'export')
    choices(export.get('scope', 'managed'), ['managed', 'scoped'], 'export.scope')
    typed(export.get('allow_partial', False), bool, 'export.allow_partial')
    for key in ('mounts', 'auth_mounts', 'entities', 'groups', 'policies', 'auth_roles', 'users', 'ldap'):
        strings(export.get(key, []), 'export.' + key)
    for key in ('destination', 'audit_destination'):
        if key in export:
            check(isinstance(export[key], str) and export[key], 'Invalid export destination')
