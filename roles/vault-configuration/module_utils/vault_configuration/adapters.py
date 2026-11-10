"""Version-gated adapters; unknown response fields fail before any write."""
import copy

from .common import check, sorted_values
from .validation import TOKEN_FIELDS

TOKEN = set(TOKEN_FIELDS) | {'token_policies'}
DEPRECATED = {'policies', 'ttl', 'max_ttl', 'period', 'bound_cidrs', 'num_uses'}


class KubernetesAdapter:
    """Preserve Kubernetes role settings while updating policies.
    RU: Сохранять настройки роли Kubernetes при изменении политик.
    """
    fields = TOKEN | {'alias_metadata', 'bound_service_account_names', 'bound_service_account_namespaces',
                      'bound_service_account_namespace_selector', 'audience', 'alias_name_source'}

    @classmethod
    def payload(cls, current, policies):
        """Build a supported role update while preserving unrelated settings.
        RU: Сформировать поддерживаемое обновление роли с сохранением остальных настроек.

        Args:
            current (dict): Current API role fields / текущие поля роли API.
            policies (list[str]): Desired token policies / желаемые политики токена.

        Returns:
            dict: Writable fields with the desired token policies / записываемые поля с желаемыми политиками токена.

        Raises:
            ConfigurationError: Unknown fields or incomplete required bindings / неизвестные поля или неполные обязательные привязки.
        """
        check(not set(current) - cls.fields - DEPRECATED, 'Unsupported Kubernetes auth role response fields')
        check(current.get('bound_service_account_names') and
              (current.get('bound_service_account_namespaces') or
               current.get('bound_service_account_namespace_selector')),
              'Incomplete Kubernetes role bindings')
        payload = {key: copy.deepcopy(value) for key, value in current.items() if key in cls.fields and value is not None}
        payload['token_policies'] = sorted_values(policies)
        return payload


class JWTAdapter:
    """Preserve JWT/OIDC role settings while updating policies.
    RU: Сохранять настройки роли JWT/OIDC при изменении политик.
    """
    fields = TOKEN | {'alias_metadata', 
        'role_type', 'bound_audiences', 'bound_subject', 'bound_claims', 'bound_claims_type',
        'user_claim', 'user_claim_json_pointer', 'groups_claim', 'claim_mappings', 'allowed_redirect_uris',
        'oidc_scopes', 'max_age', 'clock_skew_leeway', 'expiration_leeway', 'not_before_leeway',
        'verbose_oidc_logging',
    }

    @classmethod
    def payload(cls, current, policies):
        """Build a supported role update while preserving unrelated settings.
        RU: Сформировать поддерживаемое обновление роли с сохранением остальных настроек.

        Args:
            current (dict): Current API role fields / текущие поля роли API.
            policies (list[str]): Desired token policies / желаемые политики токена.

        Returns:
            dict: Writable fields with the desired token policies / записываемые поля с желаемыми политиками токена.

        Raises:
            ConfigurationError: Unknown fields or incomplete required bindings / неизвестные поля или неполные обязательные привязки.
        """
        check(not set(current) - cls.fields - DEPRECATED, 'Unsupported JWT/OIDC auth role response fields')
        check(bool(current.get('user_claim')), 'JWT/OIDC role has no user_claim')
        payload = {key: copy.deepcopy(value) for key, value in current.items() if key in cls.fields and value is not None}
        payload['token_policies'] = sorted_values(policies)
        return payload


class AppRoleAdapter:
    """Preserve AppRole settings without resending create-only fields.
    RU: Сохранять настройки AppRole без повторной отправки полей только для создания.
    """
    fields = TOKEN | {'alias_metadata', 'bind_secret_id', 'secret_id_bound_cidrs', 'secret_id_num_uses',
                      'secret_id_ttl', 'local_secret_ids'}

    @classmethod
    def payload(cls, current, policies):
        """Build a supported role update while preserving unrelated settings.
        RU: Сформировать поддерживаемое обновление роли с сохранением остальных настроек.

        Args:
            current (dict): Current API role fields / текущие поля роли API.
            policies (list[str]): Desired token policies / желаемые политики токена.

        Returns:
            dict: Writable fields with the desired token policies / записываемые поля с желаемыми политиками токена.

        Raises:
            ConfigurationError: Unknown fields or incomplete required bindings / неизвестные поля или неполные обязательные привязки.
        """
        check(not set(current) - cls.fields - DEPRECATED, 'Unsupported AppRole response fields')
        # local_secret_ids is create-only: never re-send it to an existing role.
        # RU: local_secret_ids задаётся только при создании; не отправляем его повторно существующей роли.
        payload = {key: copy.deepcopy(value) for key, value in current.items()
                   if key in cls.fields and key != 'local_secret_ids' and value is not None}
        payload['token_policies'] = sorted_values(policies)
        return payload


ADAPTERS = {'kubernetes': KubernetesAdapter, 'jwt': JWTAdapter,
            'oidc': JWTAdapter, 'approle': AppRoleAdapter}


def policies(current):
    return sorted_values(current.get('token_policies', current.get('policies', [])))


def identity_fields(kind, data):
    """Normalize identity fields for stable drift comparisons.
    RU: Нормализовать поля сущности для устойчивого сравнения дрейфа.

    Args:
        kind (str): Resource type / тип ресурса.
        data (dict): Identity API response / ответ API сущности.

    Returns:
        dict: Comparable identity fields / сравниваемые поля сущности.
    """
    fields = {'name', 'metadata', 'policies'}
    if kind == 'entity':
        fields |= {'disabled'}
    else:
        fields |= {'type', 'member_entity_ids', 'member_group_ids'}
    result = {key: copy.deepcopy(value) for key, value in data.items() if key in fields}
    result.setdefault('metadata', {})
    result['metadata'] = result['metadata'] or {}
    result['policies'] = sorted_values(result.get('policies'))
    if kind == 'group':
        for key in ('member_entity_ids', 'member_group_ids'):
            result[key] = sorted_values(result.get(key))
    return result


def alias_fields(data):
    result = {key: data[key] for key in ('name', 'canonical_id', 'mount_accessor')}
    if data.get('custom_metadata'):
        result['custom_metadata'] = data['custom_metadata']
    return result
