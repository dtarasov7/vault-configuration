"""Small TLS REST client. Never redirects credentials or reports server error bodies."""
import json
import socket
import ssl
from urllib.error import HTTPError, URLError
from urllib.parse import quote
from urllib.request import HTTPSHandler, HTTPRedirectHandler, ProxyHandler, Request, build_opener

from .common import ConfigurationError, check


class VaultHTTPError(ConfigurationError):
    """Expose HTTP status without response secrets.
    RU: Представить HTTP-статус без секретов из ответа.
    """
    def __init__(self, method, status, uncertain=False):
        self.status = status
        self.uncertain = uncertain
        super().__init__('Vault request failed: method=%s status=%s%s' %
                         (method, status, '; write outcome uncertain; reconcile before retry' if uncertain else ''))


class NoRedirect(HTTPRedirectHandler):
    """Prevent redirects from forwarding the Vault token.
    RU: Запретить перенаправления, передающие токен Vault.
    """
    def redirect_request(self, request, file_pointer, code, message, headers, new_url):
        return None


class Client:
    """Access the Vault API using one existing token.
    RU: Работать с API Vault с одним существующим токеном.
    """
    def __init__(self, connection, token):
        check(isinstance(token, str) and token and '\n' not in token and '\r' not in token,
              'A nonempty automation token is required')
        self.address = connection['address'].rstrip('/')
        self.token = token
        self.timeout = connection['timeout_seconds']
        try:
            context = ssl.create_default_context(cafile=connection.get('ca_file'))
            if not connection['validate_tls']:
                context.check_hostname = False
                context.verify_mode = ssl.CERT_NONE
            if connection.get('client_cert'):
                context.load_cert_chain(connection['client_cert'], connection['client_key'])
        except (OSError, ssl.SSLError):
            raise ConfigurationError('Cannot load TLS CA/client certificate or key') from None
        self.opener = build_opener(ProxyHandler({}), HTTPSHandler(context=context), NoRedirect())
        self.requests = []

    def request(self, method, api_path, payload=None, missing=False):
        """Send a JSON request without following redirects.
        RU: Отправить JSON-запрос без перехода по перенаправлениям.

        Args:
            method (str): HTTP method / HTTP-метод.
            api_path (str): API path without /v1/ / путь API без /v1/.
            payload (dict | None): Optional JSON body / необязательное тело JSON.
            missing (bool): Accept an absent object / допускать отсутствие объекта.

        Returns:
            dict | None: Decoded response, or None for an allowed 404 / разобранный ответ либо None для допустимого 404.

        Raises:
            ConfigurationError: Forbidden backend deletion / запрещённое удаление движка.
            VaultHTTPError: HTTP, transport or JSON failure; writes may be uncertain / ошибка HTTP, транспорта или JSON; исход записи может быть неизвестен.
        """
        check(not (method == 'DELETE' and api_path.rstrip('/').startswith(('sys/mounts/', 'sys/auth/'))),
              'Deleting secret or auth mounts is forbidden')
        # API paths are assembled from validated segments. Alias names only travel in JSON.
        url = self.address + '/v1/' + quote(api_path, safe='/')
        body = json.dumps(payload).encode('utf-8') if payload is not None else None
        headers = {'X-Vault-Token': self.token, 'Content-Type': 'application/json', 'X-Vault-Request': 'true'}
        request = Request(url, data=body, headers=headers, method=method)
        self.requests.append({'method': method, 'path': api_path})
        try:
            with self.opener.open(request, timeout=self.timeout) as response:
                raw = response.read()
            return json.loads(raw.decode('utf-8')) if raw else {}
        except HTTPError as error:
            status = error.code
            error.close()
            if status == 404 and missing:
                return None
            raise VaultHTTPError(method, status, method not in {'GET', 'LIST'} and status >= 500) from None
        except (URLError, OSError, socket.timeout, ssl.SSLError):
            raise VaultHTTPError(method, 'transport', method not in {'GET', 'LIST'}) from None
        except (ValueError, UnicodeError):
            raise VaultHTTPError(method, 'invalid-json', method not in {'GET', 'LIST'}) from None

    def read(self, api_path, missing=False):
        response = self.request('GET', api_path, missing=missing)
        return None if response is None else response.get('data', {})

    def list(self, api_path):
        response = self.request('LIST', api_path, missing=True)
        return [] if response is None else response.get('data', {}).get('keys', [])
