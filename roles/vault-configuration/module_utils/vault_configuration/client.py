"""Small TLS REST client. Never redirects credentials or reports server error bodies."""
import errno
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
    def __init__(self, method, status, uncertain=False, diagnostic=None):
        self.status = status
        self.uncertain = uncertain
        super().__init__('Vault request failed: method=%s status=%s%s' %
                         (method, status, '; write outcome uncertain; reconcile before retry' if uncertain else '') +
                         ('; ' + diagnostic if diagnostic else ''))


def transport_diagnostic(error):
    """Classify connection failures using safe, predefined messages.
    RU: Классифицировать ошибки соединения безопасными предопределёнными сообщениями.

    Args:
        error (Exception): Transport or TLS setup failure / ошибка транспорта или настройки TLS.

    Returns:
        str: Reason and troubleshooting hint without raw exception text / причина и подсказка без исходного текста исключения.
    """
    # Exception strings and URLError reasons may contain URLs, credentials or response text.
    # RU: Текст исключения и reason URLError могут содержать URL, секреты или текст ответа.
    cause = error
    while isinstance(cause, URLError):
        cause = cause.reason
    if isinstance(cause, ssl.SSLCertVerificationError):
        code = getattr(cause, 'verify_code', None)
        hints = {
            9: 'Server certificate is not yet valid; check certificate dates and the execution host clock',
            10: 'Server certificate has expired; check certificate dates and the execution host clock',
            18: 'Self-signed server certificate; configure a trusted CA on the execution host',
            19: 'Self-signed certificate in the chain; check the trusted CA and server intermediate certificates',
            20: 'Cannot find the issuer; check the trusted CA and server intermediate certificates',
            21: 'Cannot verify the certificate chain; check the trusted CA and server intermediate certificates',
            62: 'Certificate hostname mismatch; use an address covered by the certificate SAN',
            64: 'Certificate IP address mismatch; use an address covered by the certificate SAN',
        }
        hint = hints.get(code, 'Check certificate trust, chain, validity and address SAN on the execution host')
        code_detail = '; verify_code=%s' % code if type(code) is int else ''
        return 'reason=tls_certificate_verification_failed' + code_detail + '; hint=' + hint
    if isinstance(cause, ssl.SSLError):
        tls_reasons = {
            'WRONG_VERSION_NUMBER': 'Check HTTP versus HTTPS and the listener port',
            'TLSV1_ALERT_PROTOCOL_VERSION': 'Check compatible TLS versions on the client and server',
            'TLSV13_ALERT_CERTIFICATE_REQUIRED': 'Server requires a client certificate; configure client_cert and client_key',
            'TLSV1_ALERT_UNKNOWN_CA': 'Peer rejected a certificate CA; check mutual TLS trust',
            'SSLV3_ALERT_HANDSHAKE_FAILURE': 'Check TLS versions, ciphers and required client certificates',
            'PEM_LIB': 'Check PEM encoding and whether the certificate and private key match',
            'NO_CERTIFICATE_OR_CRL_FOUND': 'CA file contains no usable PEM certificates',
            'KEY_VALUES_MISMATCH': 'Client certificate and private key do not match',
        }
        reason = getattr(cause, 'reason', None)
        hint = tls_reasons.get(reason, 'Check TLS protocol, certificate files and mutual TLS requirements')
        reason_detail = '; tls_reason=' + reason if reason in tls_reasons else ''
        return 'reason=tls_error' + reason_detail + '; hint=' + hint
    if isinstance(cause, socket.gaierror):
        return 'reason=dns_resolution_failed; hint=Check address and DNS on the execution host'
    if isinstance(cause, (socket.timeout, TimeoutError)):
        return 'reason=timeout; hint=Check routing, firewall, Vault availability and timeout_seconds'
    if isinstance(cause, OSError):
        reasons = {
            errno.ECONNREFUSED: ('connection_refused', 'Check Vault listener, port and service status'),
            errno.ECONNRESET: ('connection_reset', 'Check server, load balancer and TLS listener logs'),
            errno.EPIPE: ('connection_closed', 'Check server and load balancer logs'),
            errno.ENETUNREACH: ('network_unreachable', 'Check routes from the execution host'),
            errno.EHOSTUNREACH: ('host_unreachable', 'Check routing and firewall from the execution host'),
            errno.ETIMEDOUT: ('timeout', 'Check routing, firewall, Vault availability and timeout_seconds'),
            errno.EACCES: ('permission_denied', 'Check file access and network security policy for the execution user'),
            errno.EPERM: ('permission_denied', 'Check file access and network security policy for the execution user'),
            errno.ENOENT: ('file_not_found', 'Check CA/client certificate/key paths on the execution host'),
        }
        reason, hint = reasons.get(cause.errno, ('os_error', 'Check network, TLS files and execution host logs'))
        return 'reason=' + reason + '; hint=' + hint
    return 'reason=transport_error; hint=Check DNS, connectivity and TLS from the execution host; environment proxies are disabled'


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
        self.connection_diagnostic = 'timeout_seconds=%s; tls_validation=%s; ca_source=%s; proxy=disabled' % (
            self.timeout, 'enabled' if connection['validate_tls'] else 'disabled',
            'explicit_ca_file' if connection.get('ca_file') else 'python_default_trust_store')
        tls_stage = 'load_ca'
        try:
            context = ssl.create_default_context(cafile=connection.get('ca_file'))
            if not connection['validate_tls']:
                context.check_hostname = False
                context.verify_mode = ssl.CERT_NONE
            if connection.get('client_cert'):
                tls_stage = 'load_client_certificate'
                context.load_cert_chain(connection['client_cert'], connection['client_key'])
        except (OSError, ssl.SSLError) as error:
            diagnostic = transport_diagnostic(error)
            raise ConfigurationError('Cannot load TLS CA/client certificate or key; stage=' + tls_stage +
                                     '; ' + diagnostic + '; ' + self.connection_diagnostic) from None
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
        except (URLError, OSError, socket.timeout, ssl.SSLError) as error:
            diagnostic = transport_diagnostic(error) + '; ' + self.connection_diagnostic
            raise VaultHTTPError(method, 'transport', method not in {'GET', 'LIST'}, diagnostic) from None
        except (ValueError, UnicodeError):
            raise VaultHTTPError(method, 'invalid-json', method not in {'GET', 'LIST'}) from None

    def read(self, api_path, missing=False):
        response = self.request('GET', api_path, missing=missing)
        return None if response is None else response.get('data', {})

    def list(self, api_path):
        response = self.request('LIST', api_path, missing=True)
        return [] if response is None else response.get('data', {}).get('keys', [])
