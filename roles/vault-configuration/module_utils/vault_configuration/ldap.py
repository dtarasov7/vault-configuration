"""Create-only mounts and LDAP/AD configuration; bind passwords stay outside plans and state."""
from urllib.parse import urlsplit

from .common import check
from .compiler import path
from .validation import TOKEN_FIELDS

LDAP_FIELDS = {
    'url': str, 'binddn': str, 'userdn': str, 'userattr': str, 'userfilter': str,
    'groupdn': str, 'groupattr': str, 'groupfilter': str, 'upndomain': str,
    'certificate': str, 'starttls': bool, 'insecure_tls': bool,
    'tls_min_version': str, 'tls_max_version': str, 'discoverdn': bool,
    'deny_null_bind': bool, 'anonymous_group_search': bool, 'case_sensitive_names': bool,
    'username_as_alias': bool, 'use_token_groups': bool, 'enable_samaccountname_login': bool,
    'dereference_aliases': str, 'max_page_size': int,
    'connection_timeout': int, 'request_timeout': int,
}
LDAP_FIELDS.update(TOKEN_FIELDS)


def ldap_fields(data):
    if data is None:
        return None
    # Some Vault releases return bindpass="". Never trust a response to redact secrets.
    return {key: value for key, value in data.items() if key in LDAP_FIELDS}


def validate_ldap(items):
    """Validate LDAP/AD settings and explicit insecure transport consent.
    RU: Проверить настройки LDAP/AD и явное разрешение незащищённого транспорта.

    Args:
        items (list[dict]): LDAP integrations / интеграции LDAP.

    Returns:
        None.

    Raises:
        ConfigurationError: Invalid integration settings / неверные настройки интеграции.
    """
    from .validation import fields, typed, name, unique
    if items is None:
        return
    typed(items, list, 'ldap')
    ids, mounts = set(), set()
    for item in items:
        fields(item, ['id', 'auth_mount', 'config', 'bind_password_policy', 'allow_insecure_ldap'],
               ['id', 'auth_mount', 'config'], 'ldap')
        name(item['id'], 'ldap.id')
        path(item['auth_mount'])
        check(item['id'] not in ids and item['auth_mount'] not in mounts, 'Duplicate LDAP id/auth mount')
        ids.add(item['id'])
        mounts.add(item['auth_mount'])
        fields(item['config'], LDAP_FIELDS, ['url', 'userdn', 'groupdn'], 'ldap.config')
        for key, value in item['config'].items():
            typed(value, LDAP_FIELDS[key], 'ldap.config.' + key)
            if type(value) is int:
                check(value >= 0, 'LDAP timeouts/page sizes must be nonnegative')
        typed(item.get('allow_insecure_ldap', False), bool, 'allow_insecure_ldap')
        config = item['config']
        urls = config['url'].split(',')
        for url in urls:
            origin = urlsplit(url.strip())
            check(origin.scheme in {'ldap', 'ldaps'} and origin.hostname and not origin.username and
                  not origin.password and origin.path in {'', '/'} and not origin.query and not origin.fragment,
                  'LDAP URL must contain LDAP(S) origins without credentials')
            check(origin.scheme == 'ldaps' or config.get('starttls') is True or item.get('allow_insecure_ldap') is True,
                  'Plain LDAP without StartTLS requires explicit allow_insecure_ldap: true')
        for key in ('userattr', 'groupattr'):
            if key in config:
                config[key] = config[key].lower()
        for key in ('tls_min_version', 'tls_max_version'):
            if key in config:
                check(config[key] in {'tls12', 'tls13'}, 'LDAP TLS version must be tls12 or tls13')
        if 'token_type' in config:
            check(config['token_type'] in {'service', 'batch', 'default'}, 'Invalid LDAP token_type')
        if 'token_bound_cidrs' in config:
            from .validation import strings
            strings(config['token_bound_cidrs'], 'LDAP token_bound_cidrs')
        if 'dereference_aliases' in config:
            check(config['dereference_aliases'] in {'never', 'finding', 'searching', 'always'}, 'Invalid LDAP alias dereferencing')
        policy = item.setdefault('bind_password_policy', 'on_create')
        check(policy in {'on_create', 'always'}, 'LDAP bind_password_policy must be on_create or always')


def initial_ldap_config(data):
    return bool(data is not None and not data.get('binddn') and not data.get('userdn') and
                not data.get('groupdn') and data.get('url') == 'ldap://127.0.0.1')


def ensure_auth_mount(planner, mount, auth_type, section):
    """Plan a missing auth backend and reject incompatible mounts.
    RU: Запланировать отсутствующий auth-движок и отклонить несовместимые пути.

    Args:
        planner (Planner): Mutable planning context / изменяемый контекст планирования.
        mount (str): Backend mount path / путь подключения движка.
        auth_type (str): Required authentication backend type / требуемый тип аутентификации.
        section (str): Owning inventory section / раздел инвентаря, управляющий объектом.

    Returns:
        dict | None: Existing backend details, or None for a new backend / существующие параметры движка либо None для нового.

    Raises:
        ConfigurationError: Backend type or path conflict / конфликт типа или пути движка.
    """
    details = planner.view['auth'].get(mount + '/')
    check(not details or details['type'] == auth_type, 'Auth mount already has a different type: ' + mount)
    if details:
        version = details.get('running_plugin_version', '')
        check(not version or version.startswith('v' + planner.view['version'] + '+builtin'),
              'Unsupported external auth plugin version')
    else:
        check(not any(mount.startswith(existing) or existing.rstrip('/').startswith(mount + '/')
                      for existing in planner.view['auth']),
              'New auth mount conflicts with an existing parent/child mount')
        # Vault allocates the accessor; users and aliases resolve it after auth enable.
        # RU: Vault выделяет accessor; пользователи и алиасы получают его после включения аутентификации.
        model = planner.add_model('auth_mount', mount, None, {'type': auth_type}, section, phase=1)
        model['path'] = 'sys/auth/' + mount
        planner.view['auth'][mount + '/'] = {'type': auth_type, 'accessor': {'$ref': 'auth_mount:' + mount}}
    return details


def plan_infrastructure(planner, passwords):
    """Plan missing backends and owned LDAP configuration updates.
    RU: Запланировать недостающие движки и обновление своей конфигурации LDAP.

    Args:
        planner (Planner): Mutable planning context / изменяемый контекст планирования.
        passwords (dict[str, str]): LDAP bind passwords by integration ID / пароли LDAP bind по ID интеграции.

    Returns:
        None: Adds models to the planner / добавляет модели в планировщик.

    Raises:
        ConfigurationError: Mount conflict, migration or missing bind password / конфликт путей, миграция или отсутствие bind-пароля.
    """
    for mount in planner.config['mounts']:
        if mount + '/' in planner.view['mounts']:
            continue
        check(not any(mount.startswith(existing) or existing.rstrip('/').startswith(mount + '/') for existing in planner.view['mounts']),
              'New mount conflicts with an existing parent/child mount')
        api = 'sys/mounts/' + mount
        model = planner.add_model('mount', mount, None, {'type': 'kv', 'options': {'version': '2'}},
                                  'mounts', phase=0)
        model['path'] = api
    userpass_mounts = {item['auth_mount'] for item in planner.sections.get('users') or []
                       if item['source'] == 'userpass'}
    for mount in sorted(userpass_mounts):
        ensure_auth_mount(planner, mount, 'userpass', 'users')
    for item in planner.sections.get('ldap') or []:
        mount = item['auth_mount']
        details = ensure_auth_mount(planner, mount, 'ldap', 'ldap')
        api = 'auth/' + mount + '/config'
        data = planner.view['objects'].get(api)
        entry = {'path': api, 'data': data} if data is not None else None
        payload = dict(data or {})
        payload.update(item['config'])
        # LDAP defaults are pinned for new integrations; existing settings are preserved.
        # RU: Значения LDAP по умолчанию задаём только для новых интеграций; существующие настройки сохраняем.
        if data is None:
            for key, default in [('insecure_tls', False), ('starttls', False), ('tls_min_version', 'tls12'),
                                 ('tls_max_version', 'tls13'), ('username_as_alias', True),
                                 ('case_sensitive_names', False)]:
                payload.setdefault(key, default)
        rotate = bool(item['config'].get('binddn')) and (
            data is None or initial_ldap_config(data) or data.get('binddn') != item['config']['binddn']
            or item['bind_password_policy'] == 'always')
        password = passwords.get(item['id']) if rotate else None
        check(not rotate or isinstance(password, str) and password, 'Required LDAP bind password is missing')
        model = planner.add_model('ldap_config', item['id'], entry, payload, 'ldap', phase=2, password=password)
        model.update(path=api, auth_mount=mount, secret_field='bindpass',
                     accessor=planner.view['auth'][mount + '/']['accessor'])
        model['compare_subset'] = True
        model['new_auth_mount'] = details is None
