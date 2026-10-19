"""Arquivos com permissão restrita e gravação atômica (Windows e Linux)."""
from __future__ import annotations

import os
import subprocess
from pathlib import Path


def restrict(path: str | os.PathLike) -> None:
    """Deixa o arquivo acessível só ao usuário atual (melhor esforço)."""
    path = os.fspath(path)
    try:
        if os.name == "nt":
            user = os.environ.get("USERNAME")
            if not user:
                return
            domain = os.environ.get("USERDOMAIN")
            principal = f"{domain}\\{user}" if domain else user
            subprocess.run(["icacls", path, "/inheritance:r", "/grant:r", f"{principal}:F"],
                           capture_output=True, check=False,
                           creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
        else:
            os.chmod(path, 0o600)
    except OSError:
        pass


def write_new(path: Path, data: bytes, private: bool = False) -> None:
    """Cria o arquivo; falha se ele já existir (nunca sobrescreve chaves ou certificados)."""
    mode = 0o600 if private else 0o644
    fd = os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY | getattr(os, "O_BINARY", 0), mode)
    try:
        if private:
            restrict(path)
        with os.fdopen(fd, "wb") as f:
            fd = -1
            f.write(data)
    finally:
        if fd != -1:
            os.close(fd)


def write_atomic(path: Path, data: bytes, private: bool = False) -> None:
    """Grava num temporário e troca de uma vez: quem lê nunca vê o arquivo pela metade."""
    tmp = path.with_name(path.name + ".tmp")
    try:
        os.remove(tmp)
    except FileNotFoundError:
        pass
    write_new(tmp, data, private=private)
    with open(tmp, "rb+") as f:
        os.fsync(f.fileno())
    os.replace(tmp, path)


def warn_if_exposed(path: Path) -> str | None:
    """No Linux, avisa se uma chave privada pode ser lida por outros usuários."""
    if os.name == "nt":
        return None
    try:
        mode = os.stat(path).st_mode
    except OSError:
        return None
    if mode & 0o077:
        return f"{path} tem permissão {oct(mode & 0o777)}; use chmod 600."
    return None
