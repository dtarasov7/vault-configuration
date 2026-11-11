"""Apply live plans without a registry; report confirmed and uncertain writes.
RU: Применять планы без реестра; сообщать подтверждённые записи и неопределённый исход.
"""
import copy

from .adapters import identity_fields, alias_fields, ADAPTERS, policies, TOKEN
from .common import ConfigurationError, check, digest
from .planner import resolve
from .ldap import ldap_fields, initial_ldap_config
from .reader import fingerprint, snapshot


class PartialApply(ConfigurationError):
    """Carry safe per-run outcomes; no durable journal is retained.
    RU: Передавать безопасные результаты запуска без постоянного журнала.
    """
    def __init__(self, message, confirmed, uncertain):
        super().__init__(message)
        self.confirmed = confirmed
        self.uncertain = uncertain


def projected(kind, data):
    """Keep only comparable fields for a resource kind.
    RU: Оставить только сравниваемые поля данного типа ресурса.

    Args:
        kind (str): Resource type / тип ресурса.
        data (dict | None): API object data / данные объекта API.

    Returns:
        dict | None: Comparable API representation / сравниваемое представление API.
    """
    if data is None:
        return None
    if kind == 'ldap_config':
        return ldap_fields(data)
    if kind == 'mount':
        return {'type': data['type'], 'options': data.get('options') or {}}
    if kind == 'auth_mount':
        return {'type': data['type']}
    if kind in {'entity', 'group'}:
        return identity_fields(kind, data)
    if kind.endswith('_alias'):
        return alias_fields(data)
    if kind == 'policy':
        return {'policy': data['policy']}
    if kind == 'userpass':
        result = {key: value for key, value in data.items() if key in TOKEN or (key == 'alias_metadata' and value)}
        result['token_policies'] = policies(result)
        return result
    return data


def read_object(client, kind, api_path):
    """Read a resource and normalize its comparable fields.
    RU: Прочитать ресурс и нормализовать его сравниваемые поля.

    Args:
        client (Client): Authenticated API client / аутентифицированный клиент API.
        kind (str): Resource type / тип ресурса.
        api_path (str): API path without /v1/ / путь API без /v1/.

    Returns:
        dict | None: Current fields, or None when absent / текущие поля либо None при отсутствии.

    Raises:
        VaultHTTPError: API read failed / ошибка чтения API.
    """
    if kind in {'mount', 'auth_mount'}:
        root = 'sys/mounts' if kind == 'mount' else 'sys/auth'
        mount = api_path[len(root) + 1:]
        data = client.read(root).get(mount + '/')
    else:
        data = client.read(api_path, missing=True)
    return projected(kind, data)




def preflight(client, operations):
    """Check token mutation capabilities before applying a plan.
    RU: Проверить права токена на изменения перед применением плана.

    Args:
        client (Client): Authenticated API client / аутентифицированный клиент API.
        operations (list[dict]): Planned operations / планируемые операции.

    Returns:
        None.

    Raises:
        ConfigurationError: Required capabilities are missing / отсутствуют необходимые capabilities.
        VaultHTTPError: Capability lookup failed / ошибка проверки capabilities.
    """
    paths = sorted(set(operation['path'] for operation in operations
                       if operation['action'] not in {'noop', 'forget'}))
    if not paths:
        return
    response = client.request('POST', 'sys/capabilities-self', {'paths': paths})
    capabilities = response.get('data', response)
    for operation in operations:
        if operation['action'] in {'noop', 'forget'}:
            continue
        allowed = capabilities.get(operation['path'], capabilities.get('capabilities', []))
        need = 'delete' if operation['action'] == 'delete' else 'update'
        check('root' in allowed or (need in allowed and 'deny' not in allowed),
              'Automation token lacks required mutation capabilities')
        if operation['path'].startswith(('sys/mounts/', 'sys/auth/')):
            check('root' in allowed or 'sudo' in allowed, 'Mount creation requires sudo capability')




class Executor:
    """Apply ordered mutations with drift checks and journaling.
    RU: Применять изменения по порядку с проверкой дрейфа и журналированием.
    """
    def __init__(self, client, config, planner):
        self.client, self.config, self.planner = client, config, planner
        self.identifiers = dict(planner.identifiers)
        self.confirmed = []
        self.pending = None
        self.expected = copy.deepcopy(planner.view['objects'])

    def execute(self, plan):
        """Apply ordered writes once, checking drift and never deleting objects.
        RU: Однократно выполнить записи с проверкой дрейфа без удаления объектов.

        Args:
            plan (dict): Reviewed ordered operations / согласованные упорядоченные операции.
        Returns:
            dict: Change flag and confirmed outcomes / признак изменений и подтверждённые результаты.
        Raises:
            ConfigurationError: Drift or capability failure before writes / дрейф или отсутствие прав до записи.
            PartialApply: Apply failed; inspect confirmed/uncertain / ошибка применения; проверьте confirmed/uncertain.
        """
        fresh = snapshot(self.client, self.config)
        check(fingerprint(fresh) == fingerprint(self.planner.original_view), 'Vault drifted after planning; no writes were attempted')
        preflight(self.client, plan['operations'])
        deferred = []
        try:
            deferred_done = False
            for operation in plan['operations']:
                check(operation['action'] in {'noop', 'create', 'update'}, 'Object deletion is forbidden')
                if operation['phase'] >= 40 and not deferred_done:
                    self.attach_deferred(deferred)
                    deferred_done = True
                if operation['action'] == 'noop':
                    continue
                model = self.planner.models[operation['key']]
                if operation['action'] == 'create' and model['kind'] in {'entity', 'group'}:
                    payload = {field: value for field, value in model['payload'].items()
                               if field not in {'policies', 'member_entity_ids', 'member_group_ids'}}
                    self.write(model, payload, operation)
                    deferred.append((model, operation))
                elif model['kind'] == 'group' and operation['phase'] < 40:
                    deferred.append((model, operation))
                else:
                    self.write(model, resolve(model['payload'], self.identifiers), operation)
            if not deferred_done:
                self.attach_deferred(deferred)
            return {'changed': bool(self.confirmed), 'confirmed': self.confirmed, 'uncertain': None}
        except (ConfigurationError, OSError) as error:
            message = str(error) if isinstance(error, ConfigurationError) else 'Vault I/O failed; inspect current configuration before retrying'
            raise PartialApply(message, self.confirmed, self.pending) from None

    def attach_deferred(self, deferred):
        """Attach relationships after newly created identities receive UUIDs.
        RU: Назначить связи после получения UUID новыми сущностями.

        Args:
            deferred (list[tuple]): Models and operations awaiting IDs / модели и операции, ожидающие ID.

        Returns:
            None.

        Raises:
            ConfigurationError: Drift, unresolved references or API failure / дрейф, неразрешённые ссылки или ошибка API.
        """
        for model, operation in deferred:
            payload = resolve(model['payload'], self.identifiers)
            current = self.expected.get(model['path'])
            if current != payload:
                self.write(model, payload, dict(operation, action='attach'))

    def reread(self, model):
        """Check that a live resource still matches the expected state.
        RU: Проверить соответствие текущего ресурса ожидаемому состоянию.

        Args:
            model (dict): Planned resource model / модель планируемого ресурса.

        Returns:
            dict | None: Current normalized fields / текущие нормализованные поля.

        Raises:
            ConfigurationError: Resource drift or API failure / дрейф ресурса или ошибка API.
        """
        path = model['path']
        actual = read_object(self.client, model['kind'], path)
        check(actual == self.expected.get(path), 'Affected object drifted immediately before write')
        return actual

    def write(self, model, payload, operation):
        """Write once and verify readable fields without persisting secrets.
        RU: Однократно выполнить запись и проверить читаемые поля без сохранения секретов.

        Args:
            model (dict): Planned resource model / модель планируемого ресурса.
            payload (dict): API write fields / поля для записи через API.
            operation (dict): Single planned operation / одна планируемая операция.

        Returns:
            None.

        Raises:
            ConfigurationError: Drift, collision, API failure or readback mismatch / дрейф, коллизия, ошибка API или несовпадение прочитанных данных.
        """
        creating = operation['action'] == 'create' and model['path'] not in self.expected
        before = None
        if creating:
            if model['kind'] in {'entity', 'group'}:
                check(self.client.read('identity/' + model['kind'] + '/name/' + payload['name'], missing=True) is None,
                      'Identity appeared after planning')
            elif model['kind'].endswith('_alias'):
                # Creation endpoint has no GET. A complete alias re-list checks both mount/name and canonical binding.
                # RU: У endpoint создания нет GET; полный список алиасов позволяет проверить путь, имя и каноническую привязку.
                alias_kind = model['kind'].replace('_', '-')
                for uuid in self.client.list('identity/' + alias_kind + '/id'):
                    existing = self.client.read('identity/' + alias_kind + '/id/' + uuid)
                    check(not (existing['name'] == payload['name'] and existing['mount_accessor'] == payload['mount_accessor']),
                          'Alias appeared after planning')
            elif model['kind'] == 'ldap_config' and model.get('new_auth_mount'):
                before = read_object(self.client, model['kind'], model['path'])
                check(before is None or initial_ldap_config(before), 'LDAP config was changed after auth enable')
                self.expected[model['path']] = before
            else:
                check(read_object(self.client, model['kind'], model['path']) is None, 'Object appeared after planning')
        else:
            before = self.reread(model)
        safe_payload = copy.deepcopy(payload)
        # Only per-run outcomes are retained; requests are never retried automatically.
        # RU: Храним результат только в памяти запуска; автоматически запросы не повторяем.
        self.pending = {'key': model['key'], 'action': operation['action'], 'path': model['path'],
                        'password_write': bool(model.get('password'))}
        outgoing = copy.deepcopy(payload)
        if model.get('password'):
            outgoing[model.get('secret_field', 'password')] = model['password']
        try:
            response = self.client.request('POST', model['path'], outgoing)
        except ConfigurationError as error:
            if not getattr(error, 'uncertain', True):
                self.pending = None
            raise
        if creating and (model['kind'] in {'entity', 'group'} or model['kind'].endswith('_alias')):
            uuid = response.get('data', {}).get('id')
            check(bool(uuid), 'Vault write response did not contain identity UUID; inspect live configuration')
            self.identifiers[model['key']] = uuid
            model['path'] = 'identity/' + model['kind'].replace('_', '-') + '/id/' + uuid
        if creating and model['kind'] == 'auth_mount':
            auth = self.client.read('sys/auth')
            self.identifiers[model['key']] = auth[model['id'] + '/']['accessor']
        data = read_object(self.client, model['kind'], model['path'])
        check(isinstance(data, dict), 'Vault object is unavailable during readback; inspect live configuration')
        mismatched = [field for field, value in safe_payload.items() if data.get(field) != value]
        check(not mismatched, 'Vault readback differs from write intent in fields: ' + ', '.join(mismatched))
        self.expected[model['path']] = data
        self.confirmed.append({'key': model['key'], 'action': operation['action'], 'hash': digest(data)})
        self.pending = None
        model['password'] = None

