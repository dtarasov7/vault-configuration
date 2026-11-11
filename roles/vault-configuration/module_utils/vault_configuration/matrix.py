"""Read-only KV v2 access matrices; no secret values or authentication attempts.
RU: Матрицы назначенных прав KV v2 без чтения секретов и попыток входа.
"""
import csv
import io
import json
import re
from datetime import datetime, timezone

from .common import check, ConfigurationError
from .compiler import PERMISSIONS, compile_grant, compile_personal, ENTITY_TEMPLATE
from .adapters import policies

# Public, permanent column order; each operation occupies exactly one character.
# RU: Постоянный порядок позиций: одна операция занимает ровно один символ.
POSITIONS = [('list', 'L'), ('read', 'R'), ('write', 'W'), ('patch', 'P'),
             ('read_metadata', 'M'), ('update_metadata', 'U'), ('delete_latest', 'D'),
             ('delete_versions', 'V'), ('undelete_versions', 'N'),
             ('destroy_versions', 'X'), ('delete_metadata', 'Z')]
CAPABILITIES = {'create', 'read', 'update', 'patch', 'delete', 'list', 'sudo', 'deny', 'subscribe'}
TEMPLATE = re.compile(r'\{\{identity\.entity\.aliases\.([A-Za-z0-9_-]+)\.name\}\}')
TOKEN = re.compile(r'\s+|\#[^\n]*|//[^\n]*|/\*.*?\*/|"(?:\\.|[^"\\])*"|[A-Za-z_][A-Za-z0-9_-]*|[^\s]', re.S)


def utc_now():
    """Return an ISO UTC timestamp / RU: Вернуть время UTC в формате ISO.

    Returns:
        str: Current time / текущее время.
    """
    return datetime.now(timezone.utc).isoformat()


def parse_policy(text):
    """Parse capabilities-only HCL/JSON; retain unsupported rules as unknown.
    RU: Разобрать HCL/JSON capabilities; неподдерживаемые правила оставить неизвестными.

    Args:
        text (str): Policy text / текст политики.
    Returns:
        list[dict]: Path, capabilities and restriction flag / путь, capabilities и признак ограничений.
    Raises:
        ConfigurationError: Invalid JSON or unbalanced HCL / неверный JSON либо незакрытые блоки HCL.
    """
    check(isinstance(text, str), 'Matrix policy must contain text')
    if text.lstrip().startswith('{'):
        try:
            document = json.loads(text)
        except ValueError:
            raise ConfigurationError('Matrix policy contains invalid JSON') from None
        check(isinstance(document, dict), 'Matrix JSON policy must be a mapping')
        paths = document.get('path', {})
        if not isinstance(paths, dict):
            return [{'path': '*', 'capabilities': set(), 'unknown': True, 'opaque': True}]
        rules = []
        for target, body in paths.items():
            if not isinstance(body, dict):
                rules.append({'path': target.lstrip('/'), 'capabilities': set(), 'unknown': True})
                continue
            caps = body.get('capabilities', [])
            valid = isinstance(caps, list) and all(isinstance(item, str) for item in caps)
            rules.append({'path': target.lstrip('/'), 'capabilities': set(caps) if valid else set(),
                          'unknown': not valid or bool(set(body) - {'capabilities'}) or not set(caps) <= CAPABILITIES})
        if set(document) - {'path'}:
            rules.append({'path': '*', 'capabilities': set(), 'unknown': True, 'opaque': True})
        return rules
    tokens = [match.group() for match in TOKEN.finditer(text)
              if not match.group().isspace() and not match.group().startswith(('#', '//', '/*'))]
    # Validate delimiters even for unsupported fields. Do not publish raw policy bodies.
    # RU: Проверяем скобки и в неизвестных полях; исходный текст политики не публикуем.
    stack = []
    pairs = {'}': '{', ']': '[', ')': '('}
    for token in tokens:
        if token in {'{', '[', '('}:
            stack.append(token)
        elif token in pairs:
            check(bool(stack) and stack.pop() == pairs[token], 'Matrix policy contains unbalanced HCL')
    check(not stack, 'Matrix policy contains unbalanced HCL')
    result, position = [], 0
    while position < len(tokens):
        if tokens[position] != 'path' or position + 2 >= len(tokens) or not tokens[position + 1].startswith('"') or tokens[position + 2] != '{':
            # Unknown top-level syntax may affect any KV path: never silently drop it.
            return result + [{'path': '*', 'capabilities': set(), 'unknown': True, 'opaque': True}]
        try:
            target = json.loads(tokens[position + 1])
        except ValueError:
            raise ConfigurationError('Matrix policy contains an invalid path string') from None
        end, depth = position + 3, 1
        while depth:
            if tokens[end] == '{': depth += 1
            if tokens[end] == '}': depth -= 1
            end += 1
        body = tokens[position + 3:end - 1]
        caps, unknown = set(), True
        if len(body) >= 4 and body[:3] == ['capabilities', '=', '[']:
            close = body.index(']')
            values = body[3:close]
            try:
                values = [json.loads(token) for token in values if token != ',']
                if all(isinstance(value, str) for value in values):
                    caps = set(values)
                    unknown = close != len(body) - 1 or not caps <= CAPABILITIES
            except ValueError:
                unknown = True  # Expressions remain unknown / RU: выражения остаются неизвестными.
        result.append({'path': target.lstrip('/'), 'capabilities': caps, 'unknown': unknown})
        position = end
    return result


def subject(label, entity_id=None, aliases=None, disabled=False):
    """Create a report subject / RU: Создать субъекта отчёта.

    Args:
        label (str): Unique CSV column / уникальная колонка CSV.
        entity_id (str | None): Real entity UUID / реальный UUID entity.
        aliases (dict | None): Accessor to login mapping / accessor и логин.
        disabled (bool): Disabled entity / отключённая entity.
    Returns:
        dict: Subject with direct policy sources and parent groups / субъект с политиками и родительскими группами.
    """
    return {'label': label, 'entity_id': entity_id, 'aliases': aliases or {}, 'disabled': disabled,
            'direct': {}, 'parents': set()}


def bind(item, names, origin):
    """Record policy provenance / RU: Записать происхождение политик.

    Args:
        item (dict): Subject / субъект.
        names (list[str]): Policy names / имена политик.
        origin (str): Binding source / источник назначения.
    Returns:
        None.
    """
    if isinstance(names, str): names = [name.strip() for name in names.split(',') if name.strip()]
    for name in names or []:
        item['direct'].setdefault(name, set()).add(origin)


def cluster_model(view):
    """Build subjects and group inheritance from the live snapshot.
    RU: Построить субъектов и наследование групп из снимка Vault.

    Args:
        view (dict): Snapshot including LDAP mappings / снимок, включая LDAP mappings.
    Returns:
        tuple[dict, dict, list[str]]: Subjects, policies and limitations / субъекты, политики и ограничения.
    """
    subjects, messages = {}, []
    for index, kind, prefix in [('entities', 'user', 'u:'), ('groups', 'group', 'g:')]:
        for uuid, entry in view[index].items():
            data = entry['data']
            item = subject(prefix + data['name'], uuid if kind == 'user' else None,
                           disabled=data.get('disabled', False))
            bind(item, data.get('policies', []), entry['path'])
            subjects[(kind, uuid)] = item
    accessors = {details['accessor']: mount.rstrip('/') for mount, details in view['auth'].items()}
    aliases, group_aliases = {}, {}
    for entry in view['aliases'].values():
        data = entry['data']
        mount = accessors.get(data['mount_accessor'])
        key = ('group' if entry['kind'] == 'group_alias' else 'user', data['canonical_id'])
        if key not in subjects or mount is None:
            continue
        if key[0] == 'user':
            subjects[key]['aliases'][data['mount_accessor']] = data['name']
            aliases[(mount, data['name'])] = key
        else:
            group_aliases[(mount, data['name'])] = key
    for uuid, entry in view['groups'].items():
        for field, kind in [('member_entity_ids', 'user'), ('member_group_ids', 'group')]:
            for child in entry['data'].get(field, []):
                key = (kind, child)
                if key in subjects:
                    subjects[key]['parents'].add(('group', uuid))
                else:
                    messages.append('Unresolved group member: ' + entry['path'])
    for key, entry in view.get('ldap_groups', {}).items():
        item = subject('ldap-group:' + key)
        bind(item, entry['data'].get('policies', []), entry['path'])
        alias = group_aliases.get((entry['mount'], entry['name']))
        if alias: item['parents'].add(alias)
        subjects[('ldap_group', key)] = item
    accounts = dict(view['userpass'])
    accounts.update(view.get('ldap_users', {}))
    # Include known LDAP aliases even when auth/ldap/users has no explicit mapping.
    # RU: LDAP aliases включаются и без явного назначения через auth/ldap/users.
    for mount, login in aliases:
        if view['auth'][mount + '/']['type'] in {'ldap', 'userpass'}:
            accounts.setdefault(mount + '/' + login, {'mount': mount, 'name': login, 'data': {},
                                                      'path': 'auth/' + mount + '/users/' + login})
    for account, entry in sorted(accounts.items()):
        mount = entry.get('mount') or entry['path'][5:].split('/users/', 1)[0]
        login = entry.get('name') or entry['path'].split('/users/', 1)[1]
        entity = aliases.get((mount, login))
        base = subjects.get(entity, {})
        item = subject('a:' + account, base.get('entity_id'), dict(base.get('aliases', {})), base.get('disabled', False))
        if entity: item['parents'].add(entity)
        bind(item, policies(entry['data']), entry['path'])
        config = view.get('ldap_matrix_config', {}).get(mount, {})
        bind(item, config.get('token_policies', []), 'auth/' + mount + '/config')
        if not entry['data'].get('token_no_default_policy', config.get('token_no_default_policy', False)):
            bind(item, ['default'], 'default login policy')
        local_groups = entry['data'].get('groups', []) or []
        if isinstance(local_groups, str): local_groups = [value.strip() for value in local_groups.split(',') if value.strip()]
        # Reuse observed external group membership only for this LDAP login, not for
        # other auth methods of the same entity. No directory membership is invented.
        # RU: Наблюдаемое LDAP-членство относится к этому входу, а не к другим auth methods.
        observed, pending = set(), list(base.get('parents', []))
        while pending:
            parent = pending.pop()
            if parent in observed: continue
            observed.add(parent)
            pending.extend(subjects[parent]['parents'])
        local_groups = list(local_groups) + [name for (alias_mount, name), key in group_aliases.items()
                                           if alias_mount == mount and key in observed]
        for group in local_groups:
            original_group = group
            if not config.get('case_sensitive_names', False): group = group.lower()
            reference = ('ldap_group', mount + '/' + group)
            if reference in subjects: item['parents'].add(reference)
            alias = group_aliases.get((mount, original_group)) or group_aliases.get((mount, group))
            if alias: item['parents'].add(alias)
        subjects[('account', account)] = item
    for key, entry in view['roles'].items():
        item = subject('r:' + key)
        bind(item, policies(entry['data']), entry['path'])
        if not entry['data'].get('token_no_default_policy', False): bind(item, ['default'], 'default login policy')
        subjects[('auth_role', key)] = item
    messages += ['u: columns show Identity policies and known group memberships; a: columns additionally include login policies.',
                 'LDAP membership is a Vault snapshot, not a current LDAP directory query; users who never logged in may be absent.',
                 'External group membership can change at login. Existing tokens, CIDR/TTL/use limits, Sentinel and unsupported auth methods are not evaluated.']
    return subjects, {name: entry['data']['policy'] for name, entry in view['policies'].items()}, messages


def inventory_model(config, sections):
    """Build declared assignments without resolving passwords, UUIDs or external policies.
    RU: Построить объявленные назначения без паролей, UUID и внешних политик.

    Args:
        config (dict): Validated settings / проверенные настройки.
        sections (dict): Validated declarations / проверенные объявления.
    Returns:
        tuple[dict, dict, list[str]]: Subjects, policies and limitations / субъекты, политики и ограничения.
    """
    subjects, policy_texts, messages = {}, {}, []
    for section, kind, prefix in [('users', 'user', 'u:'), ('groups', 'group', 'g:'), ('auth_roles', 'auth_role', 'r:')]:
        for entry in sections.get(section) or []:
            label = prefix + (entry['auth_mount'] + '/' if kind == 'auth_role' else '') + entry['name']
            item = subject(label, disabled=entry.get('disabled', False))
            if kind == 'user':
                item['aliases'] = {alias['auth_mount']: alias['name'] for alias in entry.get('aliases', [])}
            subjects[(kind, entry['id'])] = item
    for entry in sections.get('groups') or []:
        for field, kind in [('members', 'user'), ('member_groups', 'group')]:
            for child in entry.get(field, []):
                key = (kind, child if isinstance(child, str) else 'uuid:' + child['uuid'])
                if key not in subjects: subjects[key] = subject(('u:' if kind == 'user' else 'g:') + key[1])
                subjects[key]['parents'].add(('group', entry['id']))
    def target(reference):
        """Resolve an inventory/UUID subject / RU: Найти субъекта по inventory ID либо UUID.

        Args:
            reference (dict): Declared subject / объявленный субъект.
        Returns:
            dict: Existing or synthetic subject / существующий либо внешний субъект.
        """
        key = (reference['kind'], reference.get('id', 'uuid:' + reference.get('uuid', '')))
        if key not in subjects: subjects[key] = subject(('u:' if key[0] == 'user' else 'g:') + key[1])
        return subjects[key]
    for entry in sections.get('grants') or []:
        names = entry.get('existing_policies') or ['grant:' + entry['id']]
        if 'paths' in entry: policy_texts[names[0]] = compile_grant(entry)
        for reference in entry['subjects']: bind(target(reference), names, 'grant:' + entry['id'])
    personal = sections.get('personal_access') or {}
    if personal.get('enabled'):
        accessor = personal.get('auth_mount')
        # Offline accessors may contain '/'; use a safe synthetic accessor and remap alias keys.
        # RU: Для офлайн-шаблона используем безопасный accessor вместо пути auth mount.
        if personal.get('identity_source') == 'ldap_login':
            for item in subjects.values():
                if accessor in item['aliases']: item['aliases']['inventory_ldap'] = item['aliases'][accessor]
        policy_texts['personal'] = compile_personal(personal, 'inventory_ldap' if accessor else None)
        for reference in personal['subjects']: bind(target(reference), ['personal'], 'personal_access')
    messages += ['Only declared assignments are shown; null sections and external policies cannot predict live Vault state.',
                 'Inventory UUIDs and LDAP membership are not discovered. Unresolved personal templates remain symbolic.']
    return subjects, policy_texts, messages


def resolve_template(target, item):
    """Substitute known identity values while preserving unresolved templates.
    RU: Подставить известные значения identity, сохранив неразрешённые шаблоны.

    Args:
        target (str): ACL path / путь ACL.
        item (dict): Subject / субъект.
    Returns:
        str: Resolved or symbolic path / разрешённый либо символический путь.
    """
    if item['entity_id']:
        target = target.replace(ENTITY_TEMPLATE, item['entity_id'])
    return TEMPLATE.sub(lambda match: item['aliases'].get(match.group(1), match.group())
                        if not any(char in item['aliases'].get(match.group(1), '') for char in '*+{}') else match.group(), target)


def priority(pattern):
    """Return Vault ACL specificity / RU: Вернуть приоритет ACL Vault.

    Args:
        pattern (str): ACL pattern / шаблон ACL.
    Returns:
        tuple: Sort key / ключ сортировки.
    """
    wildcard = min([index for index, char in enumerate(pattern) if char in '*+'] or [len(pattern)])
    return wildcard, not pattern.endswith('*'), -pattern.count('+'), len(pattern), pattern


def relation(pattern, target):
    """Classify full coverage, partial overlap or disjoint literal/prefix paths.
    RU: Определить полное покрытие, частичное пересечение либо непересекающиеся пути.

    Args:
        pattern (str): ACL path / путь ACL.
        target (str): Exact path or prefix ending in '*' / точный путь либо префикс с '*'.
    Returns:
        str: full, partial or none / full, partial либо none.
    """
    p, t = pattern.rstrip('*'), target.rstrip('*')
    if pattern.endswith('*'):
        if t.startswith(p): return 'full'
        if target.endswith('*') and p.startswith(t): return 'partial'
    elif target.endswith('*'):
        if pattern.startswith(t): return 'partial'
    elif pattern == target:
        return 'full'
    return 'none'


def evaluate(rules, target, capability):
    """Evaluate a capability with exact/longest-prefix priority and conservative unknowns.
    RU: Рассчитать capability по приоритету exact/prefix с консервативной неопределённостью.

    Args:
        rules (list[dict]): Subject ACL rules / правила субъекта.
        target (str): Request path or prefix scope / путь запроса либо область префикса.
        capability (str): Required capability / необходимая capability.
    Returns:
        str: allow, deny, absent or unknown / allow, deny, absent либо unknown.
    """
    candidates, uncertain = [], []
    for rule in rules:
        pattern = rule['path']
        if rule.get('opaque'):
            uncertain.append(rule)
            continue
        unsupported_path = '+' in pattern or '*' in pattern[:-1] or '{{' in pattern
        if unsupported_path:
            fixed = re.split(r'\+|\*|\{\{', pattern, maxsplit=1)[0]
            if target.startswith(fixed) or target.endswith('*') and fixed.startswith(target[:-1]): uncertain.append(rule)
            continue
        coverage = relation(pattern, target)
        if coverage == 'full': candidates.append(rule)
    if not candidates: return 'unknown' if uncertain else 'absent'
    best = max(priority(rule['path']) for rule in candidates)
    selected = [rule for rule in candidates if priority(rule['path']) == best]
    known = set().union(*(rule['capabilities'] for rule in selected if not rule['unknown']))
    # A restriction may prohibit an otherwise granted operation. Do not infer success.
    # RU: Дополнительное ограничение может запретить разрешённую операцию; успех не предполагаем.
    unknown = uncertain or any(rule['unknown'] for rule in selected)
    if uncertain: return 'unknown'
    if 'deny' in known: return 'deny'
    if unknown: return 'unknown'
    return 'allow' if capability in known else 'absent'


def csv_value(value):
    """Escape spreadsheet formulas / RU: Экранировать формулы табличных редакторов.

    Args:
        value (str): CSV field / поле CSV.
    Returns:
        str: Safe display value / безопасное значение.
    """
    if value.lstrip().startswith(('=', '+', '-', '@')) or value.startswith(('\t', '\r', '\n')):
        return "'" + value
    return value


def build_matrix(config, sections=None, view=None, started=None):
    """Build CSV and provenance notes without API writes or local file access.
    RU: Построить CSV и пояснения без записей API и доступа к локальным файлам.

    Args:
        config (dict): Validated role settings / проверенные настройки роли.
        sections (dict | None): Offline declarations / офлайн-объявления.
        view (dict | None): Live snapshot / снимок Vault.
        started (str | None): Read start UTC / начало чтения UTC.
    Returns:
        dict: Public summary and private CSV/notes payload / сводка и содержимое CSV/пояснений.
    Raises:
        ConfigurationError: Ambiguous labels, cyclic groups or invalid policies / неоднозначные имена, циклы либо неверные политики.
    """
    source = 'cluster' if view is not None else 'inventory'
    subjects, texts, limitations = cluster_model(view) if view is not None else inventory_model(config, sections or {})
    mounts = sorted(mount.rstrip('/') for mount, data in view['mounts'].items()
                    if data.get('type') == 'kv' and str((data.get('options') or {}).get('version')) == '2') if view is not None else sorted(config['mounts'])
    parsed = {name: parse_policy(text) for name, text in texts.items()}
    labels = [item['label'] for item in subjects.values()]
    check(len(labels) == len(set(labels)), 'Matrix subject labels are ambiguous')
    cache = {}
    def inherited(key, active):
        """Collect policy sources through parent groups / RU: Собрать политики родительских групп.

        Args:
            key (tuple): Subject key / ключ субъекта.
            active (set): Active traversal path / текущая цепочка обхода.
        Returns:
            dict: Policy names and provenance chains / политики и цепочки происхождения.
        Raises:
            ConfigurationError: Group cycle / цикл групп.
        """
        check(key not in active, 'Matrix group membership cycle')
        if key in cache: return cache[key]
        item = subjects[key]
        result = {name: set(origins) for name, origins in item['direct'].items()}
        for parent in sorted(item['parents']):
            for name, origins in inherited(parent, active | {key}).items():
                result.setdefault(name, set()).update(item['label'] + ' <- ' +
                    (origin if origin.startswith(subjects[parent]['label'] + ' <- ') else subjects[parent]['label'] + ' <- ' + origin)
                    for origin in origins)
        cache[key] = result
        return result
    compiled, provenance, unknowns = {}, {}, []
    rows = {(mount, '*') for mount in mounts}
    for key, item in sorted(subjects.items()):
        bindings = inherited(key, set())
        provenance[item['label']] = {name: sorted(origins) for name, origins in sorted(bindings.items())}
        rules = []
        for name in sorted(bindings):
            entries = parsed.get(name)
            if entries is None:
                entries = [{'path': '*', 'capabilities': set(), 'unknown': True, 'opaque': True}]
                unknowns.append({'subject': item['label'], 'policy': name, 'reason': 'Policy body unavailable (including root or external inventory policy)'})
            for entry in entries:
                rule = dict(entry, path=resolve_template(entry['path'], item))
                rules.append(rule)
                if rule['unknown'] or '+' in rule['path'] or '*' in rule['path'][:-1] or '{{' in rule['path']:
                    unknowns.append({'subject': item['label'], 'policy': name, 'path': rule['path'],
                                     'reason': 'Restricted ACL, unsupported pattern or unresolved identity template'})
                for mount in mounts:
                    for api in sorted({value[0] for value in PERMISSIONS.values()}):
                        base = mount + '/' + api + '/'
                        if rule['path'].startswith(base): rows.add((mount, rule['path'][len(base):]))
        compiled[item['label']] = rules
    columns = sorted(labels)
    stream = io.StringIO(newline='')
    writer = csv.writer(stream, delimiter=';', lineterminator='\n')
    writer.writerow(['mount', 'path'] + [csv_value(label) for label in columns])
    disabled = {item['label'] for item in subjects.values() if item['disabled']}
    unknown_cells = 0
    for mount, relative in sorted(rows):
        cells = []
        for label in columns:
            cell = ''
            for permission, symbol in POSITIONS:
                api, capabilities = PERMISSIONS[permission]
                target = mount + '/' + api + '/' + relative
                if permission == 'list' and not target.endswith(('/', '*')): target += '/'
                states = [evaluate(compiled[label], target, cap) for cap in capabilities]
                if label in disabled: mark = '!'
                elif 'deny' in states: mark = '!'
                elif 'unknown' in states or len(set(states)) > 1: mark = '?'
                elif all(state == 'allow' for state in states): mark = symbol
                else: mark = '.'
                cell += mark
            unknown_cells += '?' in cell
            cells.append(cell)
        writer.writerow([csv_value(mount), csv_value(relative)] + cells)
    notes = {'source': source, 'read_started_utc': started, 'read_finished_utc': utc_now(),
             'cluster_id': view.get('cluster_id') if view is not None else None,
             'positions': [{'position': index + 1, 'symbol': symbol, 'permission': permission}
                           for index, (permission, symbol) in enumerate(POSITIONS)],
             'legend': {'.': 'No permission found within the report model / Разрешение не найдено в модели отчёта',
                        '!': 'ACL deny or disabled entity / Запрет ACL либо отключённая entity',
                        '?': 'Unknown or partial capability set / Неизвестно либо неполный набор capabilities'},
             'disabled_subjects': sorted(disabled), 'policy_sources': provenance, 'unknown_rules': unknowns,
             'limitations': limitations + [
                 'Only KV v2 operations are shown. Secret values and keys are not enumerated; rows come from policy paths.',
                 'Prefix rows show covering rules; narrower exceptions are separate rows. Consult every matching row for a concrete path.',
                 'Supported ACL paths: literal and trailing *. Most-specific matching rule wins; equal patterns combine capabilities.',
                 'Wildcards +, other identity templates, parameter constraints and unsupported syntax produce ?, not inferred access.',
                 'W requires create+update; U requires create+update on metadata. Partial capability sets produce ?.',
                 'Non-KV paths are excluded. Reading is not atomic. The report describes assignments, not every issued token.',
                 'CSV formula-like fields are prefixed with an apostrophe. Files are UTF-8 without BOM, LF, delimiter ;.']}
    return {'changed': False, 'mode': 'matrix', 'source': source, 'rows': len(rows), 'subjects': len(columns),
            'unknown_cells': unknown_cells, 'unknown_rules': len(unknowns),
            '_matrix_csv': stream.getvalue(), '_matrix_notes': json.dumps(notes, ensure_ascii=False, sort_keys=True, indent=2) + '\n'}
