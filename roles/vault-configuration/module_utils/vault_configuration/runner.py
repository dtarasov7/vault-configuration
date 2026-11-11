"""Stateless API orchestration; controller action writes all result artifacts.
RU: Работа через API без реестра; все файлы результатов записывает action на контроллере.
"""
import json

from .client import Client
from .common import check, public
from .validation import validate
from .reader import snapshot
from .planner import Planner
from .executor import Executor
from .exporter import export_configuration
from .matrix import build_matrix, utc_now


def summaries(plan):
    """Count actionable operations / RU: Подсчитать изменяющие операции.

    Args:
        plan (dict): Ordered operations / упорядоченные операции.
    Returns:
        dict: Create/update summaries / сводки создания и изменения.
    """
    result = {}
    for title, actions in [('Планируем добавить', {'create'}), ('Планируем изменить', {'update'})]:
        objects = [{'type': operation['kind'], 'name': operation['name'], 'reason': operation['reason']}
                   for operation in plan['operations'] if operation['action'] in actions]
        result[title] = {'count': len(objects), 'objects': objects}
    return result


def run(config, sections, token, passwords=None, export=None, check_mode=False, diff=False, client=None, ldap_passwords=None, matrix=None):
    """Read, plan or apply using only inventory and live Vault data.
    RU: Читать, планировать либо применять только по инвентарю и текущим данным Vault.

    Args:
        config (dict): Connection, owner and safety settings / соединение, владелец и защита.
        sections (dict): Desired sections; None leaves scope unmanaged / желаемые разделы; None исключает управление.
        token (str): Existing administrative token / существующий административный токен.
        passwords (dict | None): Local account passwords / пароли локальных пользователей.
        export (dict | None): Export filters / фильтры экспорта.
        check_mode (bool): Predict without writes / прогноз без записей.
        diff (bool): Return before/after differences / возвращать изменения до/после.
        client (Client | None): Injected API client / подставленный клиент API.
        ldap_passwords (dict | None): Bind passwords / пароли bind.
        matrix (dict | None): Matrix source / источник матрицы.
    Returns:
        dict: Sanitized report and export payload / безопасный отчёт и данные экспорта.
    Raises:
        ConfigurationError: Invalid input, incompatible API or drift / неверный ввод, несовместимый API или дрейф.
        PartialApply: Confirmed and possibly uncertain writes / подтверждённые и возможно неопределённые записи.
    """
    for label, values in [('passwords', passwords), ('ldap_passwords', ldap_passwords)]:
        check(values is None or isinstance(values, dict) and all(isinstance(key, str) and isinstance(value, str)
                                                                for key, value in values.items()),
              label + ' must map IDs to strings')
    options = export or {}
    config, sections = validate(config, sections, options)
    if config['mode'] == 'matrix':
        matrix = matrix or {}
        check(set(matrix) <= {'source'} and matrix.get('source', 'cluster') in {'cluster', 'inventory'}, 'Invalid matrix source')
        if matrix.get('source', 'cluster') == 'inventory':
            return public(build_matrix(config, sections, started=utc_now()))
    started = utc_now()
    client = client or Client(config['connection'], token)
    view = snapshot(client, config)
    warnings = [warning['reason'] for warning in view.get('warnings', [])]
    if config['mode'] == 'matrix':
        result = build_matrix(config, view=view, started=started)
        result['warnings'] = warnings
        return public(result)
    if config['mode'] == 'export':
        variables, audit = export_configuration(view, config, options)
        return {'changed': False, 'mode': 'export', 'warnings': warnings,
                'partial': audit['partial'], 'unsupported': audit['unsupported'], 'dependencies': audit['dependencies'],
                '_export_variables': variables, '_export_audit': audit}
    planner = Planner(config, sections, view, passwords, ldap_passwords)
    plan = planner.build()
    result = {'changed': False, 'mode': config['mode'], 'warnings': warnings, 'plan': plan, 'summary': summaries(plan)}
    if config['mode'] == 'dry':
        result['plan'] = dict(plan, operations=[operation for operation in plan['operations'] if operation['action'] != 'noop'])
    if diff:
        result['diff'] = [{'before_header': operation['key'], 'after_header': operation['key'],
                           'before': json.dumps(operation['before'], indent=2, sort_keys=True),
                           'after': json.dumps(operation['after'], indent=2, sort_keys=True)}
                          for operation in plan['operations'] if operation['action'] != 'noop']
    if config['mode'] == 'apply':
        if check_mode:
            result['changed'] = any(operation['action'] != 'noop' for operation in plan['operations'])
        else:
            result.update(Executor(client, config, planner).execute(plan))
    return public(result)
