"""Mode orchestration, check/diff semantics and safe public reports."""
import copy
import json
import os

try:
    import yaml
except ImportError:
    yaml = None

from .client import Client
from .common import check, public, canonical
from .state import StateStore, atomic_write
from .validation import validate
from .reader import snapshot
from .planner import Planner
from .executor import Executor, recover
from .exporter import export_configuration


def summaries(plan):
    """Group actionable operations for the public report.
    RU: Сгруппировать изменяющие операции для публичного отчёта.

    Args:
        plan (dict): Ordered operations and digest / упорядоченные операции и контрольная сумма.

    Returns:
        dict: Counts and objects by action category / количество и объекты по категориям действий.
    """
    result = {}
    for title, actions in [('Планируем добавить', {'create'}), ('Планируем изменить', {'update', 'detach'}),
                           ('Планируем удалить', {'delete', 'forget'})]:
        objects = [{'type': operation['kind'], 'name': operation['name'], 'reason': operation['reason']}
                   for operation in plan['operations'] if operation['action'] in actions]
        result[title] = {'count': len(objects), 'objects': objects}
    return result


def run(config, sections, token, passwords=None, export=None, check_mode=False, diff=False, client=None, ldap_passwords=None):
    """Run dry, apply or export with check-mode and report semantics.
    RU: Выполнить dry, apply или export с учётом check mode и отчётов.

    Args:
        config (dict): Role configuration / настройки роли.
        sections (dict): Desired sections; None leaves a section unmanaged / желаемые разделы; None исключает управление разделом.
        token (str): Existing automation token / существующий токен автоматизации.
        passwords (dict[str, str] | None): Local account passwords by ID / пароли локальных учётных записей по ID.
        export (dict | None): Export options / параметры экспорта.
        check_mode (bool): Predict changes without writing / оценивать изменения без записи.
        diff (bool): Include before/after differences / включать различия до и после.
        client (Client): Authenticated API client / аутентифицированный клиент API.
        ldap_passwords (dict[str, str] | None): LDAP bind passwords by integration ID / пароли LDAP bind по ID интеграции.

    Returns:
        dict: Mode result, plan or export paths / результат режима, план либо пути экспорта.

    Raises:
        ConfigurationError: Invalid configuration or API/state conflict / неверная конфигурация или конфликт API/реестра.
        PartialApply: Some writes completed or have an uncertain outcome / часть записей завершена либо имеет неопределённый исход.
        OSError: Local file operation failed / ошибка локальной файловой операции.
    """
    check(passwords is None or (isinstance(passwords, dict) and all(isinstance(key, str) and isinstance(value, str) for key, value in passwords.items())), 'passwords must map user IDs to strings')
    check(ldap_passwords is None or (isinstance(ldap_passwords, dict) and all(isinstance(key, str) and isinstance(value, str) for key, value in ldap_passwords.items())), 'ldap_passwords must map integration IDs to strings')
    options = export or {}
    config, sections = validate(config, sections, options)
    needs_yaml = config['mode'] == 'export' or (config['mode'] == 'dry' and config.get('report_destination'))
    check(not needs_yaml or yaml is not None,
          'PyYAML is required on the execution host for YAML exports and dry reports')
    state_path = os.path.abspath(config['management']['state_file'])
    reserved = {state_path, state_path + '.bak', state_path + '.lock',
                os.path.join(os.path.dirname(state_path), '.vault-configuration.lock')}
    outputs = []
    if config.get('report_destination'):
        outputs.append(os.path.abspath(config['report_destination']))
    if config['mode'] == 'export':
        destination = options.get('destination', './vault-access-manager-export.yml')
        outputs.extend([os.path.abspath(destination), os.path.abspath(options.get('audit_destination', destination + '.audit.json'))])
    check(not reserved.intersection(outputs) and len(outputs) == len(set(outputs)),
          'Report/export destinations must be distinct from registry, backup and lock files')
    client = client or Client(config['connection'], token)
    store = StateStore(config['management']['state_file'], config['management']['owner'])
    applying = config['mode'] == 'apply' and not check_mode
    try:
        if applying:
            store.acquire()
        view = snapshot(client, config)
        state = store.load(view['cluster_id'])
        recovered = recover(state, view, config, store, readonly=not applying)
        if config['mode'] == 'export':
            variables, audit = export_configuration(view, state, config, options)
            # Preserve escaped Vault/Jinja filters while emitting ordinary YAML mappings/lists.
            # RU: Сохраняем экранирование фильтров Vault/Jinja при выводе обычных словарей и списков YAML.
            content = yaml.safe_dump(variables, allow_unicode=True, sort_keys=True)
            audit_content = json.dumps(audit, indent=2, sort_keys=True, ensure_ascii=False) + '\n'
            destination = options.get('destination', './vault-access-manager-export.yml')
            audit_destination = options.get('audit_destination', destination + '.audit.json')
            check(destination != audit_destination and destination not in {store.filename, store.filename + '.bak', store.filename + '.lock'} and
                  audit_destination not in {store.filename, store.filename + '.bak', store.filename + '.lock'},
                  'Export files must not overwrite each other or the registry')
            # Both outputs are prepared and checked before either is written.
            # RU: Оба результата готовим и проверяем до записи первого из них.
            changed_variables = atomic_write(destination, content, check_mode=True)
            changed_audit = atomic_write(audit_destination, audit_content, check_mode=True)
            if not check_mode:
                atomic_write(destination, content)
                atomic_write(audit_destination, audit_content)
            return {'changed': changed_variables or changed_audit, 'mode': 'export',
                    'destination': destination, 'audit_destination': audit_destination,
                    'partial': audit['partial'], 'unsupported': audit['unsupported'], 'dependencies': audit['dependencies']}
        peers = store.peers(view['cluster_id'])
        planner = Planner(config, sections, view, state, peers, passwords, ldap_passwords)
        plan = planner.build()
        result = {'changed': False, 'mode': config['mode'], 'plan': plan, 'summary': summaries(plan)}
        if config['mode'] == 'dry':
            # Hide noop only in the public dry report; retain the execution plan and digest.
            # RU: Скрываем noop только в публичном dry-отчёте, сохраняя план выполнения и его сумму.
            result['plan'] = dict(plan, operations=[operation for operation in plan['operations']
                                                  if operation['action'] != 'noop'])
        if diff:
            result['diff'] = [{'before_header': operation['key'], 'after_header': operation['key'],
                               'before': json.dumps(operation['before'], indent=2, sort_keys=True),
                               'after': json.dumps(operation['after'], indent=2, sort_keys=True)}
                              for operation in plan['operations'] if operation['action'] != 'noop']
        if config['mode'] == 'apply':
            if check_mode:
                result['changed'] = recovered or any(operation['action'] != 'noop' for operation in plan['operations']) or any(
                    operation['key'] not in state['resources'] for operation in plan['operations'])
            else:
                result.update(Executor(client, config, planner, store, state).execute(plan))
                result['changed'] |= recovered
        report_destination = config.get('report_destination')
        if report_destination:
            check(report_destination not in {store.filename, store.filename + '.bak', store.filename + '.lock'},
                  'Report must not overwrite the registry')
            report = public(result)
            if config['mode'] == 'dry':
                report_content = yaml.safe_dump(report, allow_unicode=True, sort_keys=True)
            else:
                report_content = json.dumps(report, indent=2, sort_keys=True, ensure_ascii=False) + '\n'
            report_changed = atomic_write(report_destination, report_content, check_mode)
            result['changed'] |= report_changed
        return result
    finally:
        store.close()
