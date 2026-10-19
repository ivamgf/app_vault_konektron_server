"""Leitura do arquivo de configuração (TOML). Caminhos relativos partem da pasta dele."""
from __future__ import annotations

import tomllib
from dataclasses import dataclass
from pathlib import Path


class ConfigError(Exception):
    pass


@dataclass(frozen=True)
class Config:
    vault_file: Path       # arquivo do cofre publicado pelo App Vault desktop
    state_dir: Path        # estado (última geração aceita) e log de auditoria
    policy_file: Path
    api_host: str
    api_port: int
    control_port: int      # porta de operação, sempre em 127.0.0.1
    ca_file: Path          # certificado da CA interna (confia nos clientes)
    cert_file: Path        # certificado do servidor
    key_file: Path         # chave privada do servidor
    revoked_file: Path | None
    operator_cert: Path | None
    operator_key: Path | None

    @property
    def state_file(self) -> Path:
        return self.state_dir / "state.json"

    @property
    def audit_file(self) -> Path:
        return self.state_dir / "audit.log"


def _section(data: dict, name: str) -> dict:
    value = data.get(name, {})
    if not isinstance(value, dict):
        raise ConfigError(f"[{name}] deve ser uma seção.")
    return value


def _port(value: object, what: str) -> int:
    if not isinstance(value, int) or isinstance(value, bool) or not 1 <= value <= 65535:
        raise ConfigError(f"{what} deve ser uma porta entre 1 e 65535.")
    return value


def load_config(path: str | Path) -> Config:
    path = Path(path).resolve()
    try:
        data = tomllib.loads(path.read_text("utf-8"))
    except FileNotFoundError:
        raise ConfigError(f"Configuração não encontrada: {path}") from None
    except (OSError, UnicodeDecodeError, tomllib.TOMLDecodeError) as e:
        raise ConfigError(f"Configuração inválida ({path}): {e}") from None

    base = path.parent

    def file(section: dict, key: str, what: str, required: bool = True) -> Path | None:
        value = section.get(key)
        if value is None and not required:
            return None
        if not isinstance(value, str) or not value.strip():
            raise ConfigError(f"Informe {what} ({key}).")
        return (base / value).resolve()

    api, control, tls, operator = (_section(data, n) for n in ("api", "control", "tls", "operator"))
    host = api.get("host", "0.0.0.0")
    if not isinstance(host, str) or not host:
        raise ConfigError("api.host inválido.")
    api_port = _port(api.get("port", 8443), "api.port")
    control_port = _port(control.get("port", 8444), "control.port")
    if control_port == api_port:
        raise ConfigError("api.port e control.port devem ser diferentes.")

    return Config(
        vault_file=file(data, "vault_file", "o arquivo do cofre"),
        state_dir=file(data, "state_dir", "a pasta de estado"),
        policy_file=file(data, "policy_file", "o arquivo de política"),
        api_host=host,
        api_port=api_port,
        control_port=control_port,
        ca_file=file(tls, "ca", "o certificado da CA"),
        cert_file=file(tls, "cert", "o certificado do servidor"),
        key_file=file(tls, "key", "a chave do servidor"),
        revoked_file=file(tls, "revoked", "a lista de revogados", required=False),
        operator_cert=file(operator, "cert", "o certificado do operador", required=False),
        operator_key=file(operator, "key", "a chave do operador", required=False),
    )
