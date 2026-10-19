"""
appvault_client.py — lê segredos do App Vault Server (mTLS). Só biblioteca padrão.

    from appvault_client import AppVaultClient

    cofre = AppVaultClient("https://cofre.interno:8443",
                           ca_file="/etc/sistema-x/ca.pem",
                           cert_file="/etc/sistema-x/sistema-x.pem",
                           key_file="/etc/sistema-x/sistema-x.key")
    db = cofre.get("Produção", "Banco SIAFE")
    conectar(host=db.host, port=int(db.port or 5432), user=db.username, password=db.password)

Não imprima nem registre em log os valores. O repr() de um Secret não mostra os campos
secretos. Leia o segredo quando precisar dele em vez de guardá-lo por muito tempo.
"""
from __future__ import annotations

import http.client
import json
import ssl
import time
from dataclasses import dataclass, field
from urllib.parse import urlsplit

__all__ = ["AppVaultClient", "Secret", "AppVaultError", "AccessDeniedError",
           "NotFoundError", "SealedError"]


class AppVaultError(Exception):
    """Falha ao falar com o servidor ou resposta inesperada."""


class AccessDeniedError(AppVaultError):
    """O certificado não tem permissão (política) ou foi revogado."""


class NotFoundError(AppVaultError):
    """O segredo não existe no cofre publicado."""


class SealedError(AppVaultError):
    """O servidor está trancado: um operador precisa desbloqueá-lo."""


@dataclass(frozen=True, repr=False)
class Secret:
    name: str
    environment: str
    kind: str = "other"
    host: str = ""
    port: str = ""
    url: str = ""
    database: str = ""
    username: str = ""
    password: str = ""
    token: str = ""
    notes: str = ""
    extras: tuple[dict, ...] = field(default_factory=tuple)
    created_at: str = ""
    updated_at: str = ""

    def extra(self, key: str, default: str | None = None) -> str | None:
        """Valor de um campo extra pelo nome (sem diferenciar maiúsculas)."""
        for x in self.extras:
            if x.get("key", "").casefold() == key.casefold():
                return x.get("value", "")
        return default

    def __repr__(self) -> str:
        return f"Secret(environment={self.environment!r}, name={self.name!r}, kind={self.kind!r})"


_ERRORS = {403: AccessDeniedError, 404: NotFoundError, 503: SealedError}


class AppVaultClient:
    def __init__(self, url: str, *, ca_file: str, cert_file: str, key_file: str,
                 key_password: str | None = None, timeout: float = 10.0, retries: int = 2):
        parts = urlsplit(url)
        if parts.scheme != "https" or not parts.hostname:
            raise ValueError("Use uma URL https://host:porta")
        self._host, self._port = parts.hostname, parts.port or 443
        self._timeout, self._retries = timeout, retries
        ctx = ssl.create_default_context(cafile=ca_file)   # confia só na CA interna
        ctx.minimum_version = ssl.TLSVersion.TLSv1_3
        ctx.load_cert_chain(cert_file, key_file, password=key_password)
        self._ctx = ctx

    def _call(self, method: str, path: str, body: dict | None = None) -> dict:
        data = json.dumps(body).encode("utf-8") if body is not None else None
        headers = {"Content-Type": "application/json"} if data is not None else {}
        for attempt in range(self._retries + 1):
            conn = http.client.HTTPSConnection(self._host, self._port, context=self._ctx,
                                               timeout=self._timeout)
            try:
                conn.request(method, path, body=data, headers=headers)
                resp = conn.getresponse()
                raw = resp.read()
                break
            except ssl.SSLCertVerificationError as e:
                raise AppVaultError(f"Certificado do servidor não confere: {e}") from None
            except (OSError, http.client.HTTPException) as e:
                # Inclui handshake recusado (certificado do cliente revogado ou expirado).
                if attempt == self._retries:
                    raise AppVaultError(f"Falha ao falar com o App Vault Server: {e}") from None
                time.sleep(0.5 * 2 ** attempt)
            finally:
                conn.close()
        try:
            payload = json.loads(raw or b"{}")
        except ValueError:
            raise AppVaultError(f"Resposta inválida (HTTP {resp.status}).") from None
        if resp.status != 200:
            message = payload.get("error", f"HTTP {resp.status}")
            raise _ERRORS.get(resp.status, AppVaultError)(message)
        return payload

    def health(self) -> dict:
        return self._call("GET", "/v1/health")

    def list(self) -> list[dict]:
        """Segredos que este sistema pode ler: [{"environment", "name", "kind"}], sem valores."""
        return self._call("GET", "/v1/secrets")["secrets"]

    def get(self, environment: str, name: str) -> Secret:
        data = self._call("POST", "/v1/secret", {"environment": environment, "name": name})["secret"]
        known = Secret.__dataclass_fields__
        values = {k: v for k, v in data.items() if k in known}
        values["extras"] = tuple(values.get("extras") or ())
        return Secret(**values)
