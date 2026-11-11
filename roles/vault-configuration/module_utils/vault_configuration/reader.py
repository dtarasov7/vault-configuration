"""Complete supported management view. Never reads KV data or logs in."""
import re

from .adapters import ADAPTERS, TOKEN, policies, identity_fields, alias_fields
from .common import check, digest
from .ldap import ldap_fields

# The entire 2.0.x series is accepted as validated; other 2.x versions only warn.
# RU: Ветка 2.0.x считается проверенной; остальные 2.x вызывают только предупреждение.
OWNER_KEY = 'vam_owner'
ID_KEY = 'vam_id'


def snapshot(client, config):
    """Read configuration metadata without reading KV secrets.
    RU: Прочитать метаданные конфигурации без чтения секретов KV.

    Args:
        client (Client): Authenticated API client / аутентифицированный клиент API.
        config (dict): Role configuration / настройки роли.

    Returns:
        dict: Cluster, backends and managed API objects / кластер, движки и объекты API.

    Raises:
        ConfigurationError: Sealed, unsupported or incompatible Vault / запечатанный, неподдерживаемый или несовместимый Vault.
        VaultHTTPError: API read failed / ошибка чтения API.
    """
    health = client.request('GET', 'sys/health')
    check(health.get('initialized') is True and health.get('sealed') is False, 'Vault must be initialized and unsealed')
    check(bool(health.get('cluster_id')), 'Vault cluster UUID is unavailable')
    version = health.get('version')
    check(isinstance(version, str) and re.fullmatch(r'2\.[0-9]+\.[0-9]+(?:[-+][0-9A-Za-z.-]+)*', version),
          'Only Vault 2.x is supported; Vault 1.x and other major versions are unsupported')
    warnings = []
    if not version.startswith('2.0.'):
        warnings.append({'kind': 'compatibility', 'version': version,
                         'reason': 'Vault ' + version + ' is outside the validated 2.0.x series; continuing with API validation'})
    mounts = client.read('sys/mounts')
    for mount in ([] if config['mode'] == 'matrix' else config['mounts']):
        details = mounts.get(mount + '/', {})
        check(not details or (details.get('type') == 'kv' and details.get('options', {}).get('version') == '2'),
              'Existing selected mount must be KV v2; conversion/removal is forbidden')
    auth = client.read('sys/auth')
    view = {'cluster_id': health['cluster_id'], 'version': version, 'warnings': warnings, 'mounts': mounts,
            'auth': auth, 'objects': {}, 'entities': {}, 'groups': {}, 'aliases': {}, 'userpass': {},
            'roles': {}, 'policies': {}, 'ldap_groups': {}, 'ldap_users': {}, 'ldap_matrix_config': {}, 'automation_entity': '', 'ldap_external_policies': {}}
    for mount_path, details in mounts.items():
        view['objects']['sys/mounts/' + mount_path.rstrip('/')] = {
            'type': details['type'], 'options': details.get('options') or {}}
    for mount_path, details in auth.items():
        view['objects']['sys/auth/' + mount_path.rstrip('/')] = {'type': details['type']}
    token = client.read('auth/token/lookup-self')
    view['automation_entity'] = token.get('entity_id', '')
    for kind, index in [('entity', 'entities'), ('group', 'groups')]:
        for uuid in sorted(client.list('identity/' + kind + '/id')):
            data = client.read('identity/' + kind + '/id/' + uuid)
            entry = {'uuid': uuid, 'path': 'identity/' + kind + '/id/' + uuid,
                     'data': identity_fields(kind, data)}
            view[index][uuid] = entry
            view['objects'][entry['path']] = entry['data']
        alias_kind = kind + '-alias'
        for uuid in sorted(client.list('identity/' + alias_kind + '/id')):
            data = client.read('identity/' + alias_kind + '/id/' + uuid)
            entry = {'uuid': uuid, 'path': 'identity/' + alias_kind + '/id/' + uuid,
                     'kind': kind + '_alias', 'data': alias_fields(data)}
            view['aliases'][uuid] = entry
            view['objects'][entry['path']] = entry['data']
    for name in sorted(client.list('sys/policies/acl')):
        if name == 'root' or name == 'default' and config['mode'] != 'matrix':
            continue
        data = client.read('sys/policies/acl/' + name)
        entry = {'path': 'sys/policies/acl/' + name, 'data': {'policy': data['policy']}}
        view['policies'][name] = entry
        view['objects'][entry['path']] = entry['data']
    for mount_path, details in sorted(auth.items()):
        mount = mount_path.rstrip('/')
        auth_type = details['type']
        if auth_type == 'ldap':
            raw_ldap = client.read('auth/' + mount + '/config', missing=True)
            if raw_ldap and raw_ldap.get('token_policies'):
                view['ldap_external_policies'][mount] = raw_ldap['token_policies']
            if config['mode'] == 'matrix':
                view['ldap_matrix_config'][mount] = {key: (raw_ldap or {}).get(key) for key in
                    ('token_policies', 'token_no_default_policy', 'case_sensitive_names')}
                for category in ('groups', 'users'):
                    for name in sorted(client.list('auth/' + mount + '/' + category)):
                        check('/' not in name and name not in {'.', '..'}, 'Unsupported LDAP mapping name')
                        api = 'auth/' + mount + '/' + category + '/' + name
                        mapping = client.read(api)
                        view['ldap_' + category][mount + '/' + name] = {
                            'mount': mount, 'name': name, 'path': api,
                            'data': {key: mapping[key] for key in ('policies', 'groups') if key in mapping}}
            data = ldap_fields(raw_ldap)
            if data is not None:
                view['objects']['auth/' + mount + '/config'] = data
        elif auth_type == 'userpass':
            for login in sorted(client.list('auth/' + mount + '/users')):
                api = 'auth/' + mount + '/users/' + login
                data = client.read(api)
                data = {key: value for key, value in data.items() if key in TOKEN or (key == 'alias_metadata' and value)}
                data['token_policies'] = policies(data)
                view['userpass'][mount + '/' + login] = {'path': api, 'data': data}
                view['objects'][api] = data
        elif auth_type in ADAPTERS:
            for name in sorted(client.list('auth/' + mount + '/role')):
                api = 'auth/' + mount + '/role/' + name
                data = client.read(api)
                # Read-only discovery may see unsupported roles. Validate only before managing them.
                view['roles'][mount + '/' + name] = {'path': api, 'data': data, 'type': auth_type,
                                                     'mount': mount, 'name': name}
                view['objects'][api] = data
    return view


def accessor(view, mount, expected_type=None):
    """Resolve an auth accessor or retain its planned reference.
    RU: Разрешить accessor аутентификации либо сохранить плановую ссылку.

    Args:
        view (dict): Vault snapshot / снимок состояния Vault.
        mount (str): Backend mount path / путь подключения движка.
        expected_type (str | None): Required backend type, if specified / требуемый тип движка, если задан.

    Returns:
        str | dict: Existing accessor or symbolic reference / существующий accessor либо символическая ссылка.

    Raises:
        ConfigurationError: Missing or incompatible backend / отсутствующий или несовместимый движок.
    """
    data = view['auth'].get(mount + '/')
    check(data is not None, 'Referenced auth mount does not exist')
    if expected_type:
        compatible = {'jwt', 'oidc'} if expected_type in {'jwt', 'oidc'} else {expected_type}
        check(data['type'] in compatible, 'Auth mount type mismatch')
    return data['accessor']


def fingerprint(view):
    """Hash snapshot fields used to detect drift.
    RU: Вычислить хеш полей снимка для обнаружения дрейфа.

    Args:
        view (dict): Vault snapshot / снимок состояния Vault.

    Returns:
        str: Snapshot digest / контрольная сумма снимка.
    """
    return digest({'cluster_id': view['cluster_id'], 'objects': view['objects'],
                   'auth': {key: {'accessor': value['accessor'], 'type': value['type']}
                            for key, value in view['auth'].items()}})
