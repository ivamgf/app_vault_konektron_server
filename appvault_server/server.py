"""
Servidor HTTPS com mTLS. Dois listeners, com o mesmo certificado e a mesma CA:

* API (api.host:api.port), para os sistemas:
    GET  /v1/health    -> {"sealed": bool}
    GET  /v1/secrets   -> segredos que este cliente pode ler (sem valores)
    POST /v1/secret    {"environment", "name"} -> o segredo
* Operação (127.0.0.1:control.port), só para operadores, só na própria máquina:
    GET  /v1/sys/status
    POST /v1/sys/unseal  {"password", "accept_older"}
    POST /v1/sys/seal

Ao desbloquear, o cofre é aberto, todos os segredos são lidos para a memória e o arquivo
é fechado: o servidor nunca grava no cofre. A senha mestra não é guardada.
"""
from __future__ import annotations

import json
import os
import socketserver
import ssl
import sys
import threading
import time
from dataclasses import asdict
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Callable, Generic, TypeVar

from vault import Entry, Vault, VaultError, WrongPasswordError

from .audit import AuditLog
from .config import Config
from .files import write_atomic
from .policy import Policy, PolicyError, fold, load_policy

MAX_BODY = 8 * 1024
MAX_CONNECTIONS = 32
REQUEST_TIMEOUT = 10
WRONG_PASSWORD_DELAY = 2.0

T = TypeVar("T")


class HttpError(Exception):
    def __init__(self, status: int, message: str):
        super().__init__(message)
        self.status = status


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def _norm_serial(serial: str) -> str:
    return serial.strip().upper().lstrip("0")


def _load_revoked(path: Path) -> frozenset[str]:
    lines = path.read_text("ascii").splitlines()
    return frozenset(_norm_serial(s) for s in lines if s.strip() and not s.startswith("#"))


class _Reloading(Generic[T]):
    """Relê o arquivo quando ele muda. Se ficar inválido, devolve None (o servidor nega tudo)."""

    def __init__(self, path: Path, loader: Callable[[Path], T], on_error: Callable[[str], None]):
        self._path, self._loader, self._on_error = path, loader, on_error
        self._lock = threading.Lock()
        self._stamp: tuple | None = None
        self._value: T | None = None
        self._load()

    def _load(self) -> None:
        try:
            st = os.stat(self._path)
            stamp = (st.st_mtime_ns, st.st_size)
        except OSError as e:
            stamp = ("erro", str(e))
        if stamp == self._stamp:
            return
        self._stamp = stamp
        try:
            self._value = self._loader(self._path)
        except (OSError, ValueError, PolicyError) as e:
            self._value = None
            self._on_error(f"{self._path}: {e}")

    def get(self) -> T | None:
        with self._lock:
            self._load()
            return self._value


class SecretStore:
    """Segredos em memória; vazio enquanto o servidor estiver trancado."""

    def __init__(self, cfg: Config, audit: AuditLog):
        self._cfg, self._audit = cfg, audit
        self._lock = threading.Lock()
        self._unseal_lock = threading.Lock()
        self._entries: dict[tuple[str, str], Entry] | None = None
        self.generation: int | None = None
        self.content_id: str | None = None
        self.unsealed_at: str | None = None

    @property
    def sealed(self) -> bool:
        return self._entries is None

    def status(self) -> dict:
        with self._lock:
            return {"sealed": self.sealed, "generation": self.generation,
                    "content_id": self.content_id, "unsealed_at": self.unsealed_at,
                    "entries": None if self._entries is None else len(self._entries),
                    "vault_file": str(self._cfg.vault_file)}

    def _read_state(self) -> dict | None:
        try:
            state = json.loads(self._cfg.state_file.read_text("utf-8"))
        except FileNotFoundError:
            return None
        except (OSError, ValueError):
            raise HttpError(500, f"Estado ilegível: {self._cfg.state_file}") from None
        if (not isinstance(state, dict) or not isinstance(state.get("generation"), int)
                or not isinstance(state.get("content_id"), str)):
            raise HttpError(500, f"Estado inválido: {self._cfg.state_file}")
        return state

    def unseal(self, password: str, accept_older: bool, operator: str) -> dict:
        if not self._unseal_lock.acquire(blocking=False):
            raise HttpError(409, "Já há um desbloqueio em andamento.")
        try:
            try:
                with Vault.open(str(self._cfg.vault_file), password) as v:
                    generation, content_id = v.generation, v.content_id
                    entries = {(fold(e.environment), fold(e.name)): e for e in v.list_entries()}
            except WrongPasswordError:
                self._audit.write("unseal_failed", operator=operator, reason="senha incorreta")
                time.sleep(WRONG_PASSWORD_DELAY)
                raise HttpError(403, "Senha mestra incorreta.") from None
            except VaultError as e:
                self._audit.write("unseal_failed", operator=operator, reason=str(e))
                raise HttpError(422, str(e)) from None

            state = self._read_state()
            older = state is not None and (
                generation < state["generation"]
                or (generation == state["generation"] and content_id != state["content_id"]))
            if older and not accept_older:
                self._audit.write("unseal_rejected", operator=operator, generation=generation,
                                  last_generation=state["generation"])
                raise HttpError(409, f"O arquivo do cofre (geração {generation}) é anterior ou "
                                     f"diverge do último aceito (geração {state['generation']}). "
                                     "Publique a versão mais recente ou, se a volta for "
                                     "intencional, use --accept-older.")
            write_atomic(self._cfg.state_file, json.dumps(
                {"generation": generation, "content_id": content_id, "accepted_at": _now()},
                indent=2).encode("utf-8"), private=True)
            with self._lock:
                self._entries = entries
                self.generation, self.content_id, self.unsealed_at = generation, content_id, _now()
            self._audit.write("unsealed", operator=operator, generation=generation,
                              entries=len(entries), accepted_older=bool(older))
            return self.status()
        finally:
            self._unseal_lock.release()

    def seal(self, operator: str) -> None:
        with self._lock:
            self._entries = None
            self.unsealed_at = None
        self._audit.write("sealed", operator=operator)

    def get(self, environment: str, name: str) -> Entry | None:
        with self._lock:
            if self._entries is None:
                raise HttpError(503, "O servidor está trancado.")
            return self._entries.get((fold(environment), fold(name)))

    def entries(self) -> list[Entry]:
        with self._lock:
            if self._entries is None:
                raise HttpError(503, "O servidor está trancado.")
            return list(self._entries.values())


class _TLSServer(ThreadingHTTPServer):
    daemon_threads = True
    # No Windows, SO_REUSEADDR deixa outro processo "sequestrar" a porta.
    allow_reuse_address = os.name != "nt"

    def __init__(self, address, handler, context: ssl.SSLContext, app: "App"):
        self.app = app
        self._slots = threading.BoundedSemaphore(MAX_CONNECTIONS)
        super().__init__(address, handler)
        # O handshake acontece na thread de cada conexão (setup), não no accept():
        # um cliente lento não trava o servidor.
        self.socket = context.wrap_socket(self.socket, server_side=True,
                                          do_handshake_on_connect=False)

    def server_bind(self):
        socketserver.TCPServer.server_bind(self)   # sem getfqdn(), que pode ser lento
        self.server_name, self.server_port = self.server_address[:2]

    def process_request(self, request, client_address):
        if not self._slots.acquire(blocking=False):
            self.shutdown_request(request)
            return
        try:
            super().process_request(request, client_address)
        except BaseException:
            self._slots.release()
            raise

    def process_request_thread(self, request, client_address):
        try:
            super().process_request_thread(request, client_address)
        finally:
            self._slots.release()

    def handle_error(self, request, client_address):
        exc = sys.exc_info()[1]
        if isinstance(exc, (ssl.SSLError, OSError)):
            # Handshake recusado (sem certificado, CA errada...), timeout ou desconexão.
            print(f"conexão recusada de {client_address[0]}: {exc}", file=sys.stderr, flush=True)
            return
        super().handle_error(request, client_address)


class _Handler(BaseHTTPRequestHandler):
    server_version = "appvault"
    sys_version = ""
    timeout = REQUEST_TIMEOUT
    server: _TLSServer
    routes: dict[tuple[str, str], str] = {}

    def setup(self):
        self.request.settimeout(self.timeout)
        self.request.do_handshake()
        super().setup()

    def log_message(self, format, *args):  # noqa: A002 - o log que vale é o de auditoria
        pass

    @property
    def app(self) -> "App":
        return self.server.app

    def do_GET(self):
        self._dispatch("GET")

    def do_POST(self):
        self._dispatch("POST")

    def _dispatch(self, method: str) -> None:
        cn, serial = self._peer()
        try:
            name = self.routes.get((method, self.path))
            if name is None:
                raise HttpError(404, "Rota inexistente.")
            if self.app.is_revoked(serial):
                self.app.audit.write("denied", who=cn, serial=serial, ip=self.client_address[0],
                                     reason="certificado revogado", path=self.path)
                raise HttpError(403, "Certificado revogado.")
            status, body = getattr(self, name)(cn)
        except HttpError as e:
            status, body = e.status, {"error": str(e)}
        except Exception as e:  # noqa: BLE001 - nunca vazar detalhes ao cliente
            self.app.audit.write("internal_error", who=cn, path=self.path, error=type(e).__name__)
            print(f"erro interno: {e!r}", file=sys.stderr, flush=True)
            status, body = 500, {"error": "Erro interno."}
        self._reply(status, body)

    def _peer(self) -> tuple[str, str]:
        cert = self.connection.getpeercert() or {}
        cn = next((v for rdn in cert.get("subject", ()) for k, v in rdn if k == "commonName"), "")
        return cn, cert.get("serialNumber", "")

    def _body(self) -> dict:
        try:
            length = int(self.headers.get("Content-Length", "0"))
        except ValueError:
            raise HttpError(400, "Content-Length inválido.") from None
        if length < 0 or length > MAX_BODY:
            raise HttpError(413, "Requisição grande demais.")
        try:
            data = json.loads(self.rfile.read(length) or b"{}")
        except ValueError:
            raise HttpError(400, "JSON inválido.") from None
        if not isinstance(data, dict):
            raise HttpError(400, "Envie um objeto JSON.")
        return data

    def _policy(self) -> Policy:
        policy = self.app.policy()
        if policy is None:
            raise HttpError(503, "Política indisponível no servidor.")
        return policy

    def _reply(self, status: int, body: dict) -> None:
        data = json.dumps(body, ensure_ascii=False).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(data)


class ApiHandler(_Handler):
    routes = {("GET", "/v1/health"): "health",
              ("GET", "/v1/secrets"): "list_secrets",
              ("POST", "/v1/secret"): "read_secret"}

    def _client(self, cn: str) -> Policy:
        policy = self._policy()
        if not policy.is_client(cn):
            self.app.audit.write("denied", who=cn, ip=self.client_address[0],
                                 reason="não é cliente", path=self.path)
            raise HttpError(403, "Este certificado não tem acesso a segredos.")
        return policy

    def health(self, cn: str):
        return 200, {"sealed": self.app.store.sealed}

    def list_secrets(self, cn: str):
        policy = self._client(cn)
        items = [{"environment": e.environment, "name": e.name, "kind": e.kind}
                 for e in self.app.store.entries() if policy.can_read(cn, e.environment, e.name)]
        items.sort(key=lambda i: (fold(i["environment"]), fold(i["name"])))
        self.app.audit.write("list", who=cn, ip=self.client_address[0], count=len(items))
        return 200, {"secrets": items}

    def read_secret(self, cn: str):
        policy = self._client(cn)
        body = self._body()
        env, name = body.get("environment"), body.get("name")
        if not (isinstance(env, str) and isinstance(name, str) and env.strip() and name.strip()
                and len(env) <= 200 and len(name) <= 200):
            raise HttpError(400, "Informe environment e name.")
        ip = self.client_address[0]
        # A política é conferida antes de procurar: quem não tem acesso não descobre
        # se o segredo existe.
        if not policy.can_read(cn, env, name):
            self.app.audit.write("read_denied", who=cn, ip=ip, environment=env, name=name)
            raise HttpError(403, "Sem permissão para este segredo.")
        entry = self.app.store.get(env, name)
        if entry is None:
            self.app.audit.write("read_missing", who=cn, ip=ip, environment=env, name=name)
            raise HttpError(404, "Segredo não encontrado.")
        self.app.audit.write("read", who=cn, ip=ip, environment=entry.environment,
                             name=entry.name, generation=self.app.store.generation)
        return 200, {"secret": asdict(entry)}


class ControlHandler(_Handler):
    routes = {("GET", "/v1/sys/status"): "status",
              ("POST", "/v1/sys/unseal"): "unseal",
              ("POST", "/v1/sys/seal"): "seal"}

    def _operator(self, cn: str) -> None:
        if not self._policy().is_operator(cn):
            self.app.audit.write("denied", who=cn, ip=self.client_address[0],
                                 reason="não é operador", path=self.path)
            raise HttpError(403, "Este certificado não é de operador.")

    def status(self, cn: str):
        self._operator(cn)
        return 200, self.app.store.status()

    def unseal(self, cn: str):
        self._operator(cn)
        body = self._body()
        password, accept_older = body.get("password"), body.get("accept_older", False)
        if not isinstance(password, str) or not password or not isinstance(accept_older, bool):
            raise HttpError(400, "Informe a senha mestra.")
        return 200, self.app.store.unseal(password, accept_older, cn)

    def seal(self, cn: str):
        self._operator(cn)
        self.app.store.seal(cn)
        return 200, self.app.store.status()


def server_context(cfg: Config) -> ssl.SSLContext:
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_3
    ctx.verify_mode = ssl.CERT_REQUIRED
    ctx.load_verify_locations(cafile=str(cfg.ca_file))
    ctx.load_cert_chain(str(cfg.cert_file), str(cfg.key_file))
    return ctx


class App:
    def __init__(self, cfg: Config, echo_audit: bool = False):
        self.cfg = cfg
        cfg.state_dir.mkdir(parents=True, exist_ok=True)
        self.audit = AuditLog(cfg.audit_file, echo=echo_audit)
        self.store = SecretStore(cfg, self.audit)

        def problem(what: str) -> Callable[[str], None]:
            return lambda msg: self.audit.write("config_error", file=what, error=msg)

        self._policy = _Reloading(cfg.policy_file, load_policy, problem("policy"))
        self._revoked = (_Reloading(cfg.revoked_file, _load_revoked, problem("revoked"))
                         if cfg.revoked_file else None)
        ctx = server_context(cfg)
        self.api = _TLSServer((cfg.api_host, cfg.api_port), ApiHandler, ctx, self)
        self.control = _TLSServer(("127.0.0.1", cfg.control_port), ControlHandler, ctx, self)
        self._threads: list[threading.Thread] = []

    def policy(self) -> Policy | None:
        return self._policy.get()

    def is_revoked(self, serial: str) -> bool:
        if self._revoked is None:
            return False
        revoked = self._revoked.get()
        # Lista configurada mas ilegível: na dúvida, ninguém entra.
        return revoked is None or _norm_serial(serial) in revoked

    def start(self) -> None:
        for srv in (self.api, self.control):
            t = threading.Thread(target=srv.serve_forever, daemon=True)
            t.start()
            self._threads.append(t)
        self.audit.write("started", api=f"{self.cfg.api_host}:{self.api.server_port}",
                         control=f"127.0.0.1:{self.control.server_port}")

    def stop(self) -> None:
        for srv in (self.api, self.control):
            if self._threads:      # shutdown() sem serve_forever() rodando nunca retorna
                srv.shutdown()
            srv.server_close()
        if self._threads:
            self.audit.write("stopped")
        self._threads.clear()
