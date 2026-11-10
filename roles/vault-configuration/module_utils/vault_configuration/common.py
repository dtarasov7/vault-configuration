"""Canonical serialization, public errors and field projections."""
import copy
import hashlib
import json


class ConfigurationError(Exception):
    """Represent an error safe to publish.
    RU: Ошибка, текст которой безопасно публиковать.
    """


def canonical(value):
    """Serialize a value deterministically as JSON.
    RU: Сериализовать значение в JSON с устойчивым порядком.

    Args:
        value (object): Value to process / обрабатываемое значение.

    Returns:
        str: Canonical JSON / канонический JSON.

    Raises:
        TypeError: Value is not JSON serializable / значение не сериализуется в JSON.
    """
    return json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=True)


def digest(value):
    """Hash canonical JSON with SHA-256.
    RU: Вычислить SHA-256 канонического JSON.

    Args:
        value (object): Value to process / обрабатываемое значение.

    Returns:
        str: Hex digest / контрольная сумма в hex.

    Raises:
        TypeError: Value is not JSON serializable / значение не сериализуется в JSON.
    """
    return hashlib.sha256(canonical(value).encode('utf-8')).hexdigest()


def public(value):
    """Recursively remove known secret fields from a report.
    RU: Рекурсивно исключить известные секретные поля из отчёта.

    Args:
        value (object): Value to process / обрабатываемое значение.

    Returns:
        object: Sanitized copy; scalar values are unchanged / очищенная копия; скаляры не изменяются.
    """
    if isinstance(value, dict):
        return {key: public(item) for key, item in value.items()
                if key not in {'password', 'token', 'passwords', 'client_key', 'client_cert', 'bindpass', 'ldap_passwords', 'client_tls_key'}}
    if isinstance(value, list):
        return [public(item) for item in value]
    return value


def merge(defaults, supplied):
    """Deep-merge supplied settings over defaults.
    RU: Рекурсивно наложить настройки на значения по умолчанию.

    Args:
        defaults (dict): Default settings / значения по умолчанию.
        supplied (dict): Overrides / переопределения.

    Returns:
        dict: Independent merged settings / независимый объединённый словарь.
    """
    result = copy.deepcopy(defaults)
    for key, value in supplied.items():
        if isinstance(value, dict) and isinstance(result.get(key), dict):
            result[key] = merge(result[key], value)
        else:
            result[key] = copy.deepcopy(value)
    return result


def check(condition, message):
    if not condition:
        raise ConfigurationError(message)


def sorted_values(values):
    return sorted(set(values or []))
