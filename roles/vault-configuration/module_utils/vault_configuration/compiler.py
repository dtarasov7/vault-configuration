"""Compile and reverse the supported, deliberately small KV v2 ACL language."""
import json
import re

from .common import ConfigurationError, check, digest

PERMISSIONS = {
    'read': ('data', ['read']),
    'write': ('data', ['create', 'update']),
    'patch': ('data', ['patch']),
    'list': ('metadata', ['list']),
    'read_metadata': ('metadata', ['read']),
    'update_metadata': ('metadata', ['create', 'update']),
    'delete_latest': ('data', ['delete']),
    'delete_versions': ('delete', ['update']),
    'undelete_versions': ('undelete', ['update']),
    'destroy_versions': ('destroy', ['update']),
    'delete_metadata': ('metadata', ['delete']),
}
# Inventory shortcuts expand to the same canonical operations as explicit lists.
# RU: Сокращения inventory раскрываются в те же операции, что и явные списки.
PERMISSION_ALIASES = {
    'all': tuple(PERMISSIONS),
    'read_only': ('list', 'read', 'read_metadata'),
    'read_write': ('list', 'read', 'read_metadata', 'write', 'patch', 'update_metadata'),
}
SEGMENT = re.compile(r'^[A-Za-z0-9_-][A-Za-z0-9_.-]*$', re.ASCII)
ENTITY_TEMPLATE = '{{identity.entity.id}}'
LDAP_PERSONAL = re.compile(r'^(?:(?P<prefix>.+)/)?\{\{identity\.entity\.aliases\.(?P<accessor>[A-Za-z0-9_-]+)\.name\}\}/\*$')


def personal_entries(value):
    """Read legacy single policy or named policy list / RU: Прочитать одну политику либо список.

    Args:
        value (dict | list[dict] | None): Personal declarations / персональные политики.
    Returns:
        list[dict]: Policies, without mutating the input / политики без изменения входа.
    """
    return [] if value is None else value if isinstance(value, list) else [value]


def personal_identifier(item):
    """Keep legacy policy name and namespace named policies / RU: Сохранить прежнее имя и выделить имена новых политик.

    Args:
        item (dict): Personal policy / персональная политика.
    Returns:
        str: Stable policy inventory ID / постоянный ID политики.
    """
    return 'personal-' + item['id'] if 'id' in item else 'personal'


def expand_permissions(value):
    """Expand permission names and aliases into a sorted, unique operation list.
    RU: Раскрыть права и алиасы в отсортированный список уникальных операций.

    Args:
        value (str | list[str]): Permission/alias or a mixed list / право, алиас либо смешанный список.
    Returns:
        list[str]: Canonical permissions / канонические права.
    Raises:
        ConfigurationError: Empty, duplicate or unknown input / пустой ввод, повторы либо неизвестные права.
    """
    values = [value] if isinstance(value, str) else value
    check(isinstance(values, list) and values and all(isinstance(item, str) for item in values),
          'permissions must be a nonempty string or list of names')
    check(len(values) == len(set(values)), 'permissions: duplicates')
    check(set(values) <= set(PERMISSIONS) | set(PERMISSION_ALIASES), 'Unknown or empty permissions')
    expanded = set()
    for item in values:
        expanded.update(PERMISSION_ALIASES.get(item, (item,)))
    return sorted(expanded)


def path(value, root=False):
    check(isinstance(value, str), 'Path must be a string')
    if value == '' and root:
        return value
    check(bool(value) and all(SEGMENT.fullmatch(part) for part in value.split('/')),
          'Invalid path: use safe relative ASCII segments without wildcards or encoding')
    return value


def policy_name(prefix, identifier):
    return prefix + identifier + '-' + digest(identifier)[:12]


def rules_for(paths, discovery=None, personal=False, personal_template=ENTITY_TEMPLATE):
    """Translate validated KV permissions into API capabilities.
    RU: Преобразовать проверенные права KV в capabilities API.

    Args:
        paths (list[dict]): Validated paths and permissions / проверенные пути и права.
        discovery (list[dict] | None): Explicit directory LIST paths / явные пути LIST каталогов.
        personal (bool): Restrict paths to a personal subtree / ограничить пути персональным поддеревом.
        personal_template (str): Trusted identity template / доверенный шаблон идентификатора.

    Returns:
        dict[str, list[str]]: Sorted ACL rules / отсортированные правила ACL.
    """
    rules = {}
    for entry in paths:
        for permission in expand_permissions(entry['permissions']):
            api, capabilities = PERMISSIONS[permission]
            base = entry['mount'] + '/' + api + '/'
            if personal:
                targets = [base + personal_template + '/*']
            else:
                base += entry['path']
                targets = [base]
                if entry['scope'] == 'subtree':
                    targets.append(base + '/*' if entry['path'] else base + '*')
            for target in targets:
                rules.setdefault(target, set()).update(capabilities)
    for entry in discovery or []:
        target = entry['mount'] + '/metadata/' + entry['path']
        if entry['path']:
            target += '/'
        rules.setdefault(target, set()).add('list')
    return {target: sorted(capabilities) for target, capabilities in sorted(rules.items())}


def render(rules):
    return '\n'.join('path ' + json.dumps(target) + ' {\n  capabilities = ' +
                     json.dumps(capabilities) + '\n}\n'
                     for target, capabilities in sorted(rules.items()))


def compile_grant(grant):
    """Compile a validated grant into deterministic HCL.
    RU: Скомпилировать проверенное назначение прав в устойчивый HCL.

    Args:
        grant (dict): Validated grant settings / проверенные настройки прав.

    Returns:
        str: Vault ACL policy / политика ACL Vault.
    """
    return render(rules_for(grant['paths'], grant.get('discovery_paths')))


def compile_personal(personal, auth_accessor=None):
    """Compile a personal policy using an entity ID or LDAP login.
    RU: Скомпилировать персональную политику по ID сущности либо LDAP-логину.

    Args:
        personal (dict): Personal access settings / настройки персонального доступа.
        auth_accessor (str | None): Resolved LDAP backend accessor / выделенный accessor LDAP.

    Returns:
        str: HCL restricted to the personal subtree / HCL с доступом к персональному поддереву.

    Raises:
        ConfigurationError: Unsupported source, prefix or unresolved LDAP accessor / неподдерживаемый источник, префикс или неразрешённый accessor LDAP.
    """
    source = personal.get('identity_source', 'entity_id')
    check(source in {'entity_id', 'ldap_login'}, 'Unsupported personal identity source')
    template = ENTITY_TEMPLATE
    if source == 'ldap_login':
        check(isinstance(auth_accessor, str) and re.fullmatch(r'[A-Za-z0-9_-]+', auth_accessor),
              'LDAP personal policy requires a resolved safe auth accessor')
        prefix = personal.get('path_prefix', '')
        path(prefix, root=True)
        template = (prefix + '/' if prefix else '') + '{{identity.entity.aliases.' + auth_accessor + '.name}}'
    paths = [{'mount': personal['mount'], 'permissions': personal['permissions']}]
    return render(rules_for(paths, personal=True, personal_template=template))


def parse_rules(text):
    """Parse only the supported capabilities-only HCL subset.
    RU: Разобрать только поддерживаемое подмножество HCL с capabilities.

    Args:
        text (str): Input text / входной текст.

    Returns:
        dict[str, list[str]]: Parsed rules / разобранные правила.

    Raises:
        ConfigurationError: Unsupported HCL, duplicate paths or empty rules / неподдерживаемый HCL, повторные пути или пустые правила.
    """
    # Accept only blocks with capabilities. No deny, conditions, comments or HCL expressions.
    # RU: Допустимы только блоки capabilities без deny, условий, комментариев и выражений HCL.
    pattern = re.compile(r'\s*path\s+("[^"\\]*")\s*\{\s*capabilities\s*=\s*(\[[^\]]*\])\s*\}\s*')
    rules = {}
    position = 0
    while position < len(text):
        match = pattern.match(text, position)
        check(match is not None, 'Policy contains unsupported HCL; export would lose meaning')
        try:
            target = json.loads(match.group(1))
            capabilities = json.loads(match.group(2))
        except ValueError:
            raise ConfigurationError('Policy has invalid capabilities') from None
        check(isinstance(capabilities, list) and capabilities and
              all(isinstance(capability, str) for capability in capabilities),
              'Policy has invalid capabilities')
        check(target not in rules, 'Duplicate ACL blocks cannot be exported losslessly')
        rules[target] = sorted(set(capabilities))
        position = match.end()
    check(bool(rules), 'Empty policy cannot be represented as a grant')
    return rules


def reverse(text, mounts):
    """Reconstruct inventory permissions without losing ACL meaning.
    RU: Восстановить права инвентаря без потери смысла ACL.

    Args:
        text (str): Input text / входной текст.
        mounts (list[str]): Allowed KV v2 mount paths / разрешённые пути KV v2.

    Returns:
        dict: Grant or personal-access descriptor / описание назначения прав либо персонального доступа.

    Raises:
        ConfigurationError: ACL cannot be represented losslessly / ACL невозможно представить без потерь.
    """
    rules = parse_rules(text)
    remaining = dict(rules)
    paths = {}
    discovery = []
    personal = None
    for target in sorted(rules):
        if target not in remaining:
            continue
        parts = target.split('/', 2)
        check(len(parts) == 3 and parts[0] in mounts, 'Policy uses an unselected mount or API')
        mount, api, relative = parts
        capabilities = remaining.pop(target)
        candidate = None
        if relative == ENTITY_TEMPLATE + '/*':
            candidate = {'enabled': True, 'mount': mount, 'permissions': []}
        else:
            ldap_match = LDAP_PERSONAL.fullmatch(relative)
            if ldap_match:
                prefix = ldap_match.group('prefix') or ''
                path(prefix, root=True)
                candidate = {'enabled': True, 'mount': mount, 'permissions': [], 'identity_source': 'ldap_login',
                             'path_prefix': prefix, 'auth_accessor': ldap_match.group('accessor')}
        if candidate is not None:
            check(personal is None or all(personal.get(key) == candidate.get(key)
                                         for key in set(personal) | set(candidate) if key != 'permissions'),
                  'Mixed personal mounts or identity templates are unsupported')
            personal = personal or candidate
            permissions = decode(api, capabilities)
            personal['permissions'].extend(permissions)
            continue
        check(ENTITY_TEMPLATE not in relative and '*' not in relative and '+' not in relative,
              'Unpaired wildcard or unsupported Vault template')
        if relative == '' and target + '*' in remaining:
            check(remaining.pop(target + '*') == capabilities, 'Root subtree rules differ')
            paths.setdefault((mount, '', 'subtree'), []).extend(decode(api, capabilities))
            continue
        if relative.endswith('/') or relative == '':
            check(api == 'metadata' and capabilities == ['list'], 'Unsupported directory rule')
            directory = relative.rstrip('/')
            path(directory, root=True)
            discovery.append({'mount': mount, 'path': directory})
            continue
        path(relative)
        scope = 'exact'
        wildcard = target + '/*'
        if wildcard in remaining:
            check(remaining.pop(wildcard) == capabilities, 'Subtree rules differ from their base')
            scope = 'subtree'
        permissions = decode(api, capabilities)
        check('list' not in permissions or scope == 'subtree', 'Exact LIST is ambiguous')
        key = (mount, relative, scope)
        paths.setdefault(key, []).extend(permissions)
    if personal is not None:
        check(not paths and not discovery, 'Mixed personal and ordinary policy is unsupported')
        personal['permissions'] = sorted(set(personal['permissions']))
        check(parse_rules(compile_personal(personal, personal.get('auth_accessor'))) == rules, 'Unsupported personal ACL')
        return {'personal': personal}
    entries = [dict(mount=key[0], path=key[1], scope=key[2], permissions=sorted(set(value)))
               for key, value in sorted(paths.items())]
    result = {'paths': entries}
    if discovery:
        result['discovery_paths'] = discovery
    check(rules_for(entries, discovery) == rules, 'Policy cannot be exported without broadening access')
    return result


def decode(api, capabilities):
    left = set(capabilities)
    permissions = []
    for permission, (prefix, allowed) in PERMISSIONS.items():
        if api == prefix and set(allowed) <= left:
            permissions.append(permission)
            left -= set(allowed)
    check(not left, 'Unsupported ACL capabilities')
    return permissions
