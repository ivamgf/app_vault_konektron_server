"""
vault.py — Núcleo criptográfico do App Vault Protection (formato v2).

Guarda credenciais (FTP, APIs, painéis, bancos de dados, SSH, nuvem...) separadas
por ambiente, num único arquivo SQLite criptografado.

Dependência:  pip install cryptography

Desenho de segurança
--------------------
* Senha mestra -> scrypt (memory-hard) -> KEK (key-encryption key).
* Uma DEK (data-encryption key) aleatória de 256 bits fica "embrulhada" pela KEK com
  AES-256-GCM. O cabeçalho (versão, parâmetros do KDF e salt) entra como AAD desse
  embrulho: qualquer alteração nele é detectada como falha de autenticação.
* Da DEK derivam-se (HKDF) três subchaves:
    - enc_key: criptografa cada segredo e a lista de ambientes (AES-256-GCM, nonce
      aleatório por gravação);
    - idx_key: o ID de cada linha é HMAC(ambiente + nome); nomes e ambientes nunca
      ficam em texto claro no arquivo;
    - mac_key: um "manifesto" HMAC cobre todas as linhas. Apagar, duplicar ou
      restaurar uma linha antiga por fora do aplicativo é detectado ao abrir.
* Um contador de geração (coberto pelo manifesto) sobe a cada gravação. Quem guarda a
  última geração vista (o App Vault Server) detecta a volta do arquivo inteiro a uma
  versão anterior. Cofres gravados antes do contador abrem como geração 0.
* O ID da linha entra como AAD no GCM: trocar ciphertexts entre linhas é detectado.
* Trocar a senha mestra gera uma DEK NOVA e recriptografa tudo (rotação de chave),
  de modo que cópias antigas do arquivo + senha antiga vazada não abrem os dados novos.
* PRAGMA secure_delete: conteúdo apagado é sobrescrito com zeros no arquivo.
* O arquivo é criado de forma exclusiva e com permissão restrita ao usuário
  (chmod 600 no Unix; ACL via icacls no Windows).
* Parâmetros de KDF lidos do arquivo são validados (evita downgrade ou DoS de memória).
"""
from __future__ import annotations

import hashlib
import hmac
import json
import os
import secrets
import sqlite3
import string
import subprocess
import unicodedata
from contextlib import contextmanager
from dataclasses import asdict, dataclass, field, fields, replace
from datetime import datetime, timezone
from typing import Iterator

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

FORMAT_VERSION = 2
# Parâmetros do scrypt: N=2^17, r=8 -> ~128 MiB de RAM, alguns décimos de segundo.
DEFAULT_KDF = {"alg": "scrypt", "n": 2**17, "r": 8, "p": 1}
MIN_MASTER_PASSWORD_LEN = 12
DEFAULT_ENVIRONMENTS = ("Produção", "Homologação", "Desenvolvimento")
# Tipos de credencial: ftp, api, painel web, banco de dados, ssh, nuvem, outro.
KINDS = ("ftp", "api", "panel", "database", "ssh", "cloud", "other")

_MAX_LABEL_LEN = 120
_MAX_FIELD_LEN = 16_384
_MAX_NOTES_LEN = 65_536
_MAX_EXTRAS = 50
_NONCE_LEN = 12
_SALT_LEN = 16
_DEK_AAD_PREFIX = b"vault-dek-v2\x00"
_ENVS_AAD = b"vault-envs-v2"


class VaultError(Exception):
    pass


class WrongPasswordError(VaultError):
    pass


class IntegrityError(VaultError):
    pass


class EntryNotFoundError(VaultError):
    pass


class EntryExistsError(VaultError):
    pass


@dataclass
class Entry:
    name: str
    environment: str
    kind: str = "other"
    host: str = ""
    port: str = ""
    url: str = ""
    database: str = ""
    username: str = ""
    password: str = ""
    token: str = ""          # API key, token, secret access key, chave privada...
    notes: str = ""
    extras: list[dict] = field(default_factory=list)  # [{"key", "value", "secret"}]
    created_at: str = ""
    updated_at: str = ""

    @classmethod
    def from_dict(cls, data: dict) -> "Entry":
        known = {f.name for f in fields(cls)}
        return cls(**{k: v for k, v in data.items() if k in known})


# ---------------------------------------------------------------- utilitários

def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def _check_kdf(kdf: object) -> None:
    if not isinstance(kdf, dict) or kdf.get("alg") != "scrypt":
        raise VaultError("KDF não suportado.")
    n, r, p = kdf.get("n"), kdf.get("r"), kdf.get("p")
    if not all(isinstance(x, int) and not isinstance(x, bool) for x in (n, r, p)):
        raise VaultError("Parâmetros de KDF inválidos.")
    if not (2**14 <= n <= 2**20 and n & (n - 1) == 0
            and 1 <= r <= 32 and 1 <= p <= 16 and 128 * n * r <= 2**30):
        raise VaultError("Parâmetros de KDF fora dos limites aceitos.")


def _derive_kek(master_password: str, salt: bytes, kdf: dict) -> bytes:
    _check_kdf(kdf)
    pw = unicodedata.normalize("NFKC", master_password).encode("utf-8")
    n, r, p = kdf["n"], kdf["r"], kdf["p"]
    return hashlib.scrypt(pw, salt=salt, n=n, r=r, p=p, dklen=32,
                          maxmem=256 * n * r + 2**20)


def _hkdf(key: bytes, info: bytes) -> bytes:
    return HKDF(algorithm=hashes.SHA256(), length=32, salt=None, info=info).derive(key)


def _seal(key: bytes, plaintext: bytes, aad: bytes) -> tuple[bytes, bytes]:
    nonce = os.urandom(_NONCE_LEN)
    return nonce, AESGCM(key).encrypt(nonce, plaintext, aad)


def _header_aad(version: str, kdf_json: str, salt: bytes) -> bytes:
    return (_DEK_AAD_PREFIX + version.encode() + b"\x00"
            + kdf_json.encode() + b"\x00" + salt)


def _frame(*parts: bytes) -> bytes:
    """Concatena com prefixo de tamanho, para o hash não ser ambíguo."""
    out = bytearray()
    for part in parts:
        if not isinstance(part, bytes):
            raise IntegrityError("Arquivo do cofre corrompido.")
        out += len(part).to_bytes(4, "big") + part
    return bytes(out)


def _clean_label(value: object, what: str) -> str:
    """Nomes de segredos, ambientes e campos extras: uma linha, sem caracteres invisíveis."""
    if not isinstance(value, str):
        raise VaultError(f"{what} é inválido.")
    value = unicodedata.normalize("NFC", value).strip()
    if not value:
        raise VaultError(f"{what} não pode ficar vazio.")
    if len(value) > _MAX_LABEL_LEN:
        raise VaultError(f"{what} é muito longo (máximo de {_MAX_LABEL_LEN} caracteres).")
    # Cc = controle, Cf = formatação (zero-width, override bidirecional...).
    if any(unicodedata.category(c) in ("Cc", "Cf") for c in value):
        raise VaultError(f"{what} contém caracteres de controle ou invisíveis.")
    return value


def _clean_value(value: object, what: str, multiline: bool = False,
                 limit: int = _MAX_FIELD_LEN) -> str:
    if not isinstance(value, str):
        raise VaultError(f"O campo {what} é inválido.")
    if len(value) > limit:
        raise VaultError(f"O campo {what} é muito longo (máximo de {limit} caracteres).")
    allowed = "\n\r\t" if multiline else ""
    if any(unicodedata.category(c) == "Cc" and c not in allowed for c in value):
        raise VaultError(f"O campo {what} contém caracteres de controle.")
    return value


def _key(label: str) -> bytes:
    """Chave de comparação: 'Produção' e 'produção' são o mesmo ambiente."""
    return label.casefold().encode("utf-8")


def _check_master_password(pw: object) -> None:
    if not isinstance(pw, str):
        raise VaultError("Senha mestra inválida.")
    pw = unicodedata.normalize("NFKC", pw)
    if len(pw) < MIN_MASTER_PASSWORD_LEN:
        raise VaultError(f"Use uma senha mestra com pelo menos {MIN_MASTER_PASSWORD_LEN} caracteres.")
    if len(set(pw)) < 6:
        raise VaultError("Senha mestra muito previsível: use mais caracteres diferentes.")


def _restrict_permissions(path: str) -> None:
    """Deixa o arquivo acessível só ao usuário atual (melhor esforço)."""
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


def _create_exclusive(path: str) -> None:
    try:
        fd = os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY | getattr(os, "O_BINARY", 0), 0o600)
    except FileExistsError:
        raise VaultError(f"Já existe um arquivo em {path}") from None
    os.close(fd)
    _restrict_permissions(path)


def _connect(path: str) -> sqlite3.Connection:
    # isolation_level=None: as transações são abertas explicitamente (BEGIN IMMEDIATE).
    conn = sqlite3.connect(path, isolation_level=None)
    try:
        conn.execute("PRAGMA secure_delete = ON")
        conn.execute("PRAGMA journal_mode = DELETE")
    except BaseException:
        conn.close()
        raise
    return conn


def _read_meta(conn: sqlite3.Connection) -> dict:
    return dict(conn.execute("SELECT key, value FROM meta").fetchall())


def _blob(meta: dict, key: str, length: int | None = None) -> bytes:
    value = meta.get(key)
    if not isinstance(value, bytes) or (length is not None and len(value) != length):
        raise IntegrityError("Arquivo do cofre corrompido.")
    return value


def _generation(meta: dict) -> int:
    value = meta.get("generation", 0)
    if not isinstance(value, int) or isinstance(value, bool) or value < 0:
        raise IntegrityError("Arquivo do cofre corrompido.")
    return value


def _text(meta: dict, key: str) -> str:
    value = meta.get(key)
    if not isinstance(value, str):
        raise IntegrityError("Arquivo do cofre corrompido.")
    return value


def generate_password(length: int = 20, symbols: bool = True) -> str:
    """Gera uma senha aleatória com o CSPRNG do sistema, com todas as classes presentes."""
    if not 8 <= length <= 256:
        raise ValueError("O tamanho deve ficar entre 8 e 256.")
    classes = [string.ascii_lowercase, string.ascii_uppercase, string.digits]
    if symbols:
        classes.append("!@#$%&*()-_=+[]{}:,.?")
    alphabet = "".join(classes)
    while True:
        pw = "".join(secrets.choice(alphabet) for _ in range(length))
        if all(any(c in cls for c in pw) for cls in classes):
            return pw


# ---------------------------------------------------------------- o cofre

class Vault:
    """Use Vault.create(...) ou Vault.open(...); de preferência com 'with'."""

    def __init__(self, conn: sqlite3.Connection, dek: bytes, path: str, wrapped: bytes):
        self._conn = conn
        self.path = path
        self._wrapped = wrapped  # identifica a "época" da chave; muda ao trocar a senha
        self._set_keys(dek)

    def _set_keys(self, dek: bytes) -> None:
        self._dek = dek
        self._enc_key = _hkdf(dek, b"vault-enc-v2")
        self._idx_key = _hkdf(dek, b"vault-idx-v2")
        self._mac_key = _hkdf(dek, b"vault-mac-v2")

    # ---- criação / abertura

    @classmethod
    def create(cls, path: str, master_password: str, kdf: dict | None = None,
               environments: tuple[str, ...] | list[str] = DEFAULT_ENVIRONMENTS) -> "Vault":
        _check_master_password(master_password)
        kdf = dict(kdf or DEFAULT_KDF)
        _check_kdf(kdf)
        envs: list[str] = []
        for env in environments:
            env = _clean_label(env, "O ambiente")
            if all(_key(e) != _key(env) for e in envs):
                envs.append(env)
        if not envs:
            raise VaultError("Informe pelo menos um ambiente.")

        version, kdf_json = str(FORMAT_VERSION), json.dumps(kdf, sort_keys=True)
        salt, dek = os.urandom(_SALT_LEN), os.urandom(32)
        kek = _derive_kek(master_password, salt, kdf)
        nonce, wrapped = _seal(kek, dek, _header_aad(version, kdf_json, salt))

        _create_exclusive(path)
        conn = None
        try:
            conn = _connect(path)
            vault = cls(conn, dek, path, wrapped)
            with vault._tx(check_epoch=False):
                conn.execute("CREATE TABLE meta (key TEXT PRIMARY KEY, value BLOB NOT NULL)")
                conn.execute("CREATE TABLE entries (id BLOB PRIMARY KEY, nonce BLOB NOT NULL,"
                             " ciphertext BLOB NOT NULL)")
                conn.executemany("INSERT INTO meta VALUES (?, ?)", [
                    ("version", version), ("kdf", kdf_json), ("salt", salt),
                    ("dek_nonce", nonce), ("dek_wrapped", wrapped)])
                vault._store_envs(envs)
        except BaseException:
            if conn is not None:
                conn.close()
            try:
                os.remove(path)
            except OSError:
                pass
            raise
        return vault

    @classmethod
    def open(cls, path: str, master_password: str) -> "Vault":
        if not os.path.isfile(path):
            raise VaultError(f"Cofre não encontrado: {path}")
        conn = None
        try:
            conn = _connect(path)
            meta = _read_meta(conn)
            version = meta.get("version")
            if version != str(FORMAT_VERSION):
                raise VaultError(f"Versão de cofre não suportada: {version!r}")
            dek, wrapped = cls._unwrap(meta, master_password)
            vault = cls(conn, dek, path, wrapped)
            vault._verify_manifest()
            vault._load_envs()
            return vault
        except sqlite3.DatabaseError:
            if conn is not None:
                conn.close()
            raise VaultError("O arquivo não é um cofre válido.") from None
        except BaseException:
            if conn is not None:
                conn.close()
            raise

    @staticmethod
    def _unwrap(meta: dict, master_password: str) -> tuple[bytes, bytes]:
        version, kdf_json = _text(meta, "version"), _text(meta, "kdf")
        salt = _blob(meta, "salt", _SALT_LEN)
        nonce = _blob(meta, "dek_nonce", _NONCE_LEN)
        wrapped = _blob(meta, "dek_wrapped")
        try:
            kdf = json.loads(kdf_json)
        except ValueError:
            raise IntegrityError("Arquivo do cofre corrompido.") from None
        kek = _derive_kek(master_password, salt, kdf)
        try:
            dek = AESGCM(kek).decrypt(nonce, wrapped, _header_aad(version, kdf_json, salt))
        except InvalidTag:
            raise WrongPasswordError("Senha mestra incorreta.") from None
        return dek, wrapped

    # ---- transações e integridade

    @contextmanager
    def _tx(self, check_epoch: bool = True) -> Iterator[None]:
        self._conn.execute("BEGIN IMMEDIATE")
        try:
            if check_epoch:
                # Outra instância trocou a senha (e a DEK) enquanto este cofre estava aberto.
                current = _read_meta(self._conn).get("dek_wrapped")
                if current != self._wrapped:
                    raise VaultError("O cofre foi alterado por outra janela. Bloqueie e abra novamente.")
            yield
            self._conn.execute("INSERT OR REPLACE INTO meta VALUES ('generation', ?)",
                               (_generation(_read_meta(self._conn)) + 1,))
            self._write_manifest()
        except BaseException:
            self._conn.execute("ROLLBACK")
            raise
        self._conn.execute("COMMIT")

    def _compute_manifest(self) -> bytes:
        h = hmac.new(self._mac_key, b"vault-manifest-v2", hashlib.sha256)
        for eid, nonce, ct in self._conn.execute(
                "SELECT id, nonce, ciphertext FROM entries ORDER BY id"):
            h.update(hashlib.sha256(_frame(eid, nonce, ct)).digest())
        envs = self._conn.execute("SELECT value FROM meta WHERE key = 'envs'").fetchone()
        h.update(hashlib.sha256(_frame(b"envs", envs[0] if envs else b"")).digest())
        meta = _read_meta(self._conn)
        if "generation" in meta:  # ausente só em cofres gravados antes do contador
            h.update(hashlib.sha256(_frame(b"generation",
                                           str(_generation(meta)).encode())).digest())
        return h.digest()

    def _write_manifest(self) -> None:
        self._conn.execute("INSERT OR REPLACE INTO meta VALUES ('manifest', ?)",
                           (self._compute_manifest(),))

    def _verify_manifest(self) -> None:
        stored = _read_meta(self._conn).get("manifest")
        if not isinstance(stored, bytes) or not hmac.compare_digest(stored, self._compute_manifest()):
            raise IntegrityError("Falha de integridade: o arquivo do cofre foi alterado "
                                 "fora do aplicativo.")

    @property
    def generation(self) -> int:
        """Número de gravações do cofre; só aumenta (também em backups e trocas de senha)."""
        return _generation(_read_meta(self._conn))

    @property
    def content_id(self) -> str:
        """Identifica o conteúdo atual (hash do manifesto); muda a cada gravação."""
        return hashlib.sha256(_blob(_read_meta(self._conn), "manifest")).hexdigest()

    # ---- ambientes

    def _store_envs(self, envs: list[str]) -> None:
        nonce, ct = _seal(self._enc_key, json.dumps(envs, ensure_ascii=False).encode("utf-8"),
                          _ENVS_AAD)
        self._conn.execute("INSERT OR REPLACE INTO meta VALUES ('envs', ?)", (nonce + ct,))

    def _load_envs(self) -> list[str]:
        blob = _blob(_read_meta(self._conn), "envs")
        try:
            envs = json.loads(AESGCM(self._enc_key).decrypt(blob[:_NONCE_LEN], blob[_NONCE_LEN:],
                                                            _ENVS_AAD))
        except (InvalidTag, ValueError):
            raise IntegrityError("Lista de ambientes corrompida ou adulterada.") from None
        if not isinstance(envs, list) or not all(isinstance(e, str) for e in envs):
            raise IntegrityError("Lista de ambientes corrompida.")
        return envs

    def _canonical_env(self, name: str, envs: list[str] | None = None) -> str:
        name = _clean_label(name, "O ambiente")
        for env in envs if envs is not None else self._load_envs():
            if _key(env) == _key(name):
                return env
        raise VaultError(f"Ambiente inexistente: {name}")

    def environments(self) -> list[str]:
        return self._load_envs()

    def add_environment(self, name: str) -> str:
        name = _clean_label(name, "O ambiente")
        with self._tx():
            envs = self._load_envs()
            if any(_key(e) == _key(name) for e in envs):
                raise VaultError(f"O ambiente “{name}” já existe.")
            self._store_envs(envs + [name])
        return name

    def rename_environment(self, old: str, new: str) -> str:
        new = _clean_label(new, "O ambiente")
        with self._tx():
            envs = self._load_envs()
            old = self._canonical_env(old, envs)
            if new == old:
                return new
            if _key(new) != _key(old) and any(_key(e) == _key(new) for e in envs):
                raise VaultError(f"O ambiente “{new}” já existe.")
            # O ID de cada linha depende do ambiente: as entradas dele são regravadas.
            for row in self._conn.execute("SELECT id, nonce, ciphertext FROM entries").fetchall():
                entry = self._decrypt_row(*row)
                if entry.environment == old:
                    self._conn.execute("DELETE FROM entries WHERE id = ?", (row[0],))
                    self._insert(replace(entry, environment=new))
            self._store_envs([new if e == old else e for e in envs])
        return new

    def delete_environment(self, name: str) -> None:
        with self._tx():
            envs = self._load_envs()
            env = self._canonical_env(name, envs)
            count = sum(1 for e in self._iter_entries() if e.environment == env)
            if count:
                raise VaultError(f"O ambiente “{env}” ainda tem {count} segredo(s). "
                                 "Mova ou exclua os segredos antes.")
            if len(envs) == 1:
                raise VaultError("O cofre precisa ter pelo menos um ambiente.")
            self._store_envs([e for e in envs if e != env])

    # ---- segredos

    def _entry_id(self, environment: str, name: str) -> bytes:
        msg = b"entry\x00" + _key(environment) + b"\x00" + _key(name)
        return hmac.new(self._idx_key, msg, hashlib.sha256).digest()

    def _insert(self, entry: Entry) -> None:
        eid = self._entry_id(entry.environment, entry.name)
        plaintext = json.dumps(asdict(entry), ensure_ascii=False).encode("utf-8")
        nonce, ct = _seal(self._enc_key, plaintext, eid)
        self._conn.execute("INSERT INTO entries VALUES (?, ?, ?)", (eid, nonce, ct))

    def _decrypt_row(self, eid: bytes, nonce: bytes, ct: bytes) -> Entry:
        try:
            data = AESGCM(self._enc_key).decrypt(nonce, ct, eid)
            entry = Entry.from_dict(json.loads(data))
        except (InvalidTag, ValueError, TypeError):
            raise IntegrityError("Entrada corrompida ou adulterada.") from None
        if not hmac.compare_digest(eid, self._entry_id(entry.environment, entry.name)):
            raise IntegrityError("Entrada corrompida ou adulterada.")
        return entry

    def _iter_entries(self) -> Iterator[Entry]:
        for row in self._conn.execute("SELECT id, nonce, ciphertext FROM entries").fetchall():
            yield self._decrypt_row(*row)

    def _exists(self, eid: bytes) -> bool:
        return self._conn.execute("SELECT 1 FROM entries WHERE id = ?", (eid,)).fetchone() is not None

    def _validate(self, entry: Entry, envs: list[str]) -> Entry:
        if entry.kind not in KINDS:
            raise VaultError(f"Tipo de credencial inválido: {entry.kind!r}")
        port = _clean_value(entry.port, "porta").strip()
        if port and not (port.isdigit() and 1 <= int(port) <= 65535):
            raise VaultError("A porta deve ser um número entre 1 e 65535.")
        if not isinstance(entry.extras, list) or len(entry.extras) > _MAX_EXTRAS:
            raise VaultError(f"Use no máximo {_MAX_EXTRAS} campos extras.")
        extras, seen = [], set()
        for x in entry.extras:
            if not isinstance(x, dict):
                raise VaultError("Campo extra inválido.")
            key = _clean_label(x.get("key"), "O nome do campo extra")
            if _key(key) in seen:
                raise VaultError(f"Campo extra repetido: {key}")
            seen.add(_key(key))
            extras.append({"key": key,
                           "value": _clean_value(x.get("value", ""), key, multiline=True),
                           "secret": bool(x.get("secret"))})
        return replace(
            entry,
            name=_clean_label(entry.name, "O nome"),
            environment=self._canonical_env(entry.environment, envs),
            host=_clean_value(entry.host, "host").strip(),
            port=port,
            url=_clean_value(entry.url, "URL").strip(),
            database=_clean_value(entry.database, "banco").strip(),
            username=_clean_value(entry.username, "usuário").strip(),
            password=_clean_value(entry.password, "senha"),
            token=_clean_value(entry.token, "token", multiline=True),
            notes=_clean_value(entry.notes, "observações", multiline=True, limit=_MAX_NOTES_LEN),
            extras=extras,
        )

    def list_entries(self, environment: str | None = None) -> list[Entry]:
        envs = self._load_envs()
        env = self._canonical_env(environment, envs) if environment else None
        order = {e: i for i, e in enumerate(envs)}
        items = [e for e in self._iter_entries() if env is None or e.environment == env]
        items.sort(key=lambda e: (order.get(e.environment, len(order)), e.name.casefold()))
        return items

    def get(self, environment: str, name: str) -> Entry:
        env = self._canonical_env(environment)
        name = _clean_label(name, "O nome")
        eid = self._entry_id(env, name)
        row = self._conn.execute(
            "SELECT nonce, ciphertext FROM entries WHERE id = ?", (eid,)).fetchone()
        if row is None:
            raise EntryNotFoundError(f"Segredo não encontrado: {env} / {name}")
        return self._decrypt_row(eid, *row)

    def add(self, entry: Entry) -> Entry:
        """Cria um segredo novo; falha se já existir um com o mesmo nome no ambiente."""
        with self._tx():
            entry = self._validate(entry, self._load_envs())
            if self._exists(self._entry_id(entry.environment, entry.name)):
                raise EntryExistsError(f"Já existe “{entry.name}” no ambiente “{entry.environment}”.")
            now = _now()
            entry = replace(entry, created_at=now, updated_at=now)
            self._insert(entry)
        return entry

    def update(self, old_environment: str, old_name: str, entry: Entry) -> Entry:
        """Substitui um segredo; permite renomear ou mover para outro ambiente."""
        with self._tx():
            envs = self._load_envs()
            entry = self._validate(entry, envs)
            old_id = self._entry_id(self._canonical_env(old_environment, envs),
                                    _clean_label(old_name, "O nome"))
            row = self._conn.execute(
                "SELECT nonce, ciphertext FROM entries WHERE id = ?", (old_id,)).fetchone()
            if row is None:
                raise EntryNotFoundError(f"Segredo não encontrado: {old_environment} / {old_name}")
            current = self._decrypt_row(old_id, *row)
            new_id = self._entry_id(entry.environment, entry.name)
            if new_id != old_id and self._exists(new_id):
                raise EntryExistsError(f"Já existe “{entry.name}” no ambiente “{entry.environment}”.")
            self._conn.execute("DELETE FROM entries WHERE id = ?", (old_id,))
            entry = replace(entry, created_at=current.created_at or _now(), updated_at=_now())
            self._insert(entry)
        return entry

    def delete(self, environment: str, name: str) -> None:
        with self._tx():
            eid = self._entry_id(self._canonical_env(environment), _clean_label(name, "O nome"))
            cur = self._conn.execute("DELETE FROM entries WHERE id = ?", (eid,))
            if cur.rowcount == 0:
                raise EntryNotFoundError(f"Segredo não encontrado: {environment} / {name}")

    # ---- manutenção

    def verify_master_password(self, password: str) -> None:
        dek, _ = self._unwrap(_read_meta(self._conn), password)
        if not hmac.compare_digest(dek, self._dek):
            raise WrongPasswordError("Senha mestra incorreta.")

    def change_master_password(self, old_password: str, new_password: str) -> None:
        """Troca a senha mestra e rotaciona a DEK, recriptografando todo o cofre."""
        self.verify_master_password(old_password)
        _check_master_password(new_password)
        if old_password == new_password:
            raise VaultError("A nova senha deve ser diferente da atual.")
        meta = _read_meta(self._conn)
        version, kdf_json = _text(meta, "version"), _text(meta, "kdf")
        salt, new_dek = os.urandom(_SALT_LEN), os.urandom(32)
        kek = _derive_kek(new_password, salt, json.loads(kdf_json))
        nonce, wrapped = _seal(kek, new_dek, _header_aad(version, kdf_json, salt))

        old_dek = self._dek
        try:
            with self._tx():
                entries, envs = list(self._iter_entries()), self._load_envs()
                self._set_keys(new_dek)
                self._conn.execute("DELETE FROM entries")
                for entry in entries:
                    self._insert(entry)
                self._store_envs(envs)
                self._conn.executemany("UPDATE meta SET value = ? WHERE key = ?", [
                    (salt, "salt"), (nonce, "dek_nonce"), (wrapped, "dek_wrapped")])
        except BaseException:
            self._set_keys(old_dek)
            raise
        self._wrapped = wrapped

    def backup(self, dest: str, overwrite: bool = False) -> None:
        """Copia o cofre (ainda criptografado, com a senha mestra atual) para dest."""
        dest = os.path.abspath(dest)
        if os.path.exists(dest):
            if os.path.samefile(dest, self.path):
                raise VaultError("O backup não pode sobrescrever o próprio cofre.")
            if not overwrite:
                raise VaultError(f"Já existe um arquivo em {dest}")
            os.remove(dest)
        _create_exclusive(dest)
        target = sqlite3.connect(dest)
        try:
            self._conn.backup(target)
        finally:
            target.close()

    def close(self) -> None:
        # Python não garante apagar chaves da memória; aqui apenas soltamos as referências.
        if self._conn is not None:
            self._conn.close()
        self._conn = None
        self._dek = self._enc_key = self._idx_key = self._mac_key = None

    def __enter__(self) -> "Vault":
        return self

    def __exit__(self, *exc) -> None:
        self.close()
