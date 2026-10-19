"""
Log de auditoria: uma linha JSON por evento, encadeada por SHA-256.

Cada linha guarda o hash da anterior ("prev") e o seu próprio ("hash"). Editar, apagar
ou inserir uma linha no meio quebra a cadeia, e ``audit-verify`` aponta onde.
Quem controla o servidor pode reescrever a cadeia inteira; por isso cada evento também
sai na saída padrão (journald / log do serviço) para ser enviado a outro servidor.

Valores de segredos nunca entram no log; nomes de ambientes e segredos, sim.
"""
from __future__ import annotations

import hashlib
import json
import os
import sys
import threading
from datetime import datetime, timezone
from pathlib import Path

GENESIS = "0" * 64
_TAIL_BYTES = 64 * 1024


def _digest(record: dict) -> str:
    body = json.dumps(record, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(body.encode("utf-8")).hexdigest()


def _last_line(path: Path) -> bytes | None:
    try:
        with open(path, "rb") as f:
            f.seek(0, os.SEEK_END)
            size = f.tell()
            f.seek(max(0, size - _TAIL_BYTES))
            lines = f.read().splitlines()
    except FileNotFoundError:
        return None
    return lines[-1] if lines else None


class AuditLog:
    def __init__(self, path: Path, echo: bool = False):
        self.path = path
        self.echo = echo
        self._lock = threading.Lock()
        self._prev = GENESIS
        tail = _last_line(path)
        broken = False
        if tail is not None:
            try:
                rec = json.loads(tail)
                self._prev = rec["hash"]
                if not isinstance(self._prev, str) or len(self._prev) != 64:
                    raise ValueError
            except (ValueError, KeyError, TypeError):
                # Gravação interrompida ou adulteração: continua, mas registra a quebra.
                self._prev, broken = hashlib.sha256(tail).hexdigest(), True
        if not path.exists():
            fd = os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
            os.close(fd)
        if broken:
            self.write("audit_tail_invalid")

    def write(self, event: str, **fields: object) -> None:
        with self._lock:
            record = {"ts": datetime.now(timezone.utc).isoformat(timespec="milliseconds"),
                      "event": event, **fields, "prev": self._prev}
            record["hash"] = _digest(record)
            line = json.dumps(record, ensure_ascii=False, sort_keys=True,
                              separators=(",", ":")) + "\n"
            with open(self.path, "a", encoding="utf-8", newline="\n") as f:
                f.write(line)
                f.flush()
                os.fsync(f.fileno())
            self._prev = record["hash"]
            if self.echo:
                sys.stdout.write("audit " + line)
                sys.stdout.flush()


def verify(path: Path) -> tuple[int, list[str]]:
    """Confere a cadeia inteira. Devolve (linhas válidas, problemas encontrados)."""
    problems: list[str] = []
    prev, count = GENESIS, 0
    with open(path, "rb") as f:
        for n, raw in enumerate(f, 1):
            try:
                rec = json.loads(raw)
                stored = rec.pop("hash")
            except (ValueError, KeyError, TypeError, AttributeError):
                problems.append(f"linha {n}: ilegível")
                prev = hashlib.sha256(raw.rstrip(b"\r\n")).hexdigest()
                continue
            if rec.get("prev") != prev:
                problems.append(f"linha {n}: não segue a linha anterior (removida ou alterada?)")
            if _digest(rec) != stored:
                problems.append(f"linha {n}: conteúdo alterado")
            prev = stored
            count += 1
    return count, problems
