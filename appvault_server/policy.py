"""
Política de acesso: quem é operador e o que cada sistema pode ler.

Exemplo (TOML)::

    operators = ["operador-01"]

    [clients.sistema-x]
    allow = [
      { environment = "Produção", name = "Banco SIAFE" },
      { environment = "Produção", name = "SFTP *" },      # curingas: * ? [abc]
    ]

As identidades são o CN do certificado de cliente. Ambientes e nomes são comparados
sem diferenciar maiúsculas de minúsculas, como no App Vault.
"""
from __future__ import annotations

import re
import tomllib
import unicodedata
from dataclasses import dataclass
from fnmatch import fnmatchcase
from pathlib import Path

CN_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$")


class PolicyError(Exception):
    pass


def fold(value: str) -> str:
    return unicodedata.normalize("NFC", value).strip().casefold()


@dataclass(frozen=True)
class Rule:
    environment: str   # padrão já normalizado
    name: str

    def matches(self, environment: str, name: str) -> bool:
        return fnmatchcase(fold(environment), self.environment) and fnmatchcase(fold(name), self.name)


@dataclass(frozen=True)
class Policy:
    operators: frozenset[str]
    clients: dict[str, tuple[Rule, ...]]

    def is_operator(self, cn: str) -> bool:
        return cn in self.operators

    def is_client(self, cn: str) -> bool:
        return cn in self.clients

    def can_read(self, cn: str, environment: str, name: str) -> bool:
        return any(r.matches(environment, name) for r in self.clients.get(cn, ()))


def _identity(value: object, where: str) -> str:
    if not isinstance(value, str) or not CN_RE.match(value):
        raise PolicyError(f"{where}: identidade inválida {value!r} "
                          "(use letras, números, ponto, hífen e sublinhado).")
    return value


def parse_policy(data: dict) -> Policy:
    unknown = set(data) - {"operators", "clients"}
    if unknown:
        raise PolicyError(f"Chaves desconhecidas na política: {', '.join(sorted(unknown))}")
    ops = data.get("operators", [])
    if not isinstance(ops, list):
        raise PolicyError("operators deve ser uma lista.")
    operators = frozenset(_identity(o, "operators") for o in ops)

    raw_clients = data.get("clients", {})
    if not isinstance(raw_clients, dict):
        raise PolicyError("[clients] deve ser uma seção.")
    clients: dict[str, tuple[Rule, ...]] = {}
    for cn, body in raw_clients.items():
        cn = _identity(cn, "clients")
        if cn in operators:
            raise PolicyError(f"{cn} não pode ser operador e cliente ao mesmo tempo.")
        if not isinstance(body, dict) or set(body) - {"allow"}:
            raise PolicyError(f"clients.{cn}: use apenas allow = [...].")
        allow = body.get("allow", [])
        if not isinstance(allow, list):
            raise PolicyError(f"clients.{cn}.allow deve ser uma lista.")
        rules = []
        for rule in allow:
            if (not isinstance(rule, dict) or set(rule) != {"environment", "name"}
                    or not all(isinstance(v, str) and v.strip() for v in rule.values())):
                raise PolicyError(f"clients.{cn}.allow: cada regra precisa de environment e name.")
            rules.append(Rule(fold(rule["environment"]), fold(rule["name"])))
        clients[cn] = tuple(rules)
    return Policy(operators, clients)


def load_policy(path: Path) -> Policy:
    try:
        return parse_policy(tomllib.loads(Path(path).read_text("utf-8")))
    except FileNotFoundError:
        raise PolicyError(f"Política não encontrada: {path}") from None
    except (OSError, UnicodeDecodeError, tomllib.TOMLDecodeError) as e:
        raise PolicyError(f"Política inválida ({path}): {e}") from None
