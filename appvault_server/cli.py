"""
Linha de comando:  python -m appvault_server <comando> ...

  serve         inicia o servidor (trancado)
  unseal        desbloqueia (ou recarrega após publicar um cofre novo)
  seal          tranca: descarta os segredos da memória
  status        mostra o estado
  check         valida configuração, política e permissões
  audit-verify  confere a cadeia do log de auditoria
  ca ...        CA interna: init, issue, revoke, list
"""
from __future__ import annotations

import argparse
import getpass
import http.client
import json
import os
import signal
import ssl
import sys
import threading
from pathlib import Path

from . import __version__
from . import audit as audit_mod
from . import ca as ca_mod
from .config import Config, ConfigError, load_config
from .files import warn_if_exposed
from .policy import PolicyError, load_policy


class CliError(Exception):
    pass


def _new_secret(prompt: str) -> str:
    first = getpass.getpass(prompt)
    if getpass.getpass("Repita: ") != first:
        raise CliError("As senhas não conferem.")
    return first


# ---------------------------------------------------------------- servidor

def cmd_serve(args) -> int:
    from .server import App   # importa vault/cryptography só quando precisa

    cfg = load_config(args.config)
    # Como serviço, a saída pode não ser UTF-8; um nome de segredo não pode derrubar o log.
    for stream in (sys.stdout, sys.stderr):
        stream.reconfigure(encoding="utf-8", errors="backslashreplace")
    for warning in _warnings(cfg):
        print(f"aviso: {warning}", file=sys.stderr)
    if os.name != "nt":
        import resource
        # Sem core dump: ele levaria os segredos da memória para o disco.
        resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    app = App(cfg, echo_audit=True)
    stop = threading.Event()
    signal.signal(signal.SIGINT, lambda *_: stop.set())
    if hasattr(signal, "SIGTERM"):
        signal.signal(signal.SIGTERM, lambda *_: stop.set())
    app.start()
    print(f"App Vault Server {__version__}: API em {cfg.api_host}:{app.api.server_port}, "
          f"operação em 127.0.0.1:{app.control.server_port}. Trancado; use 'unseal'.",
          flush=True)
    try:
        while not stop.wait(1):
            pass
    finally:
        app.stop()
    return 0


def _warnings(cfg: Config) -> list[str]:
    out = []
    for path in (cfg.key_file, cfg.operator_key):
        if path is not None:
            w = warn_if_exposed(path)
            if w:
                out.append(w)
    if cfg.revoked_file is None:
        out.append("tls.revoked não configurado: revogar certificados não terá efeito.")
    return out


def cmd_check(args) -> int:
    cfg = load_config(args.config)
    policy = load_policy(cfg.policy_file)
    for path in (cfg.ca_file, cfg.cert_file, cfg.key_file, cfg.vault_file):
        if not path.is_file():
            raise CliError(f"Arquivo não encontrado: {path}")
    from .server import server_context
    server_context(cfg)    # valida certificado + chave + CA
    print(f"Configuração ok. Operadores: {', '.join(sorted(policy.operators)) or '(nenhum)'}; "
          f"clientes: {', '.join(sorted(policy.clients)) or '(nenhum)'}.")
    for warning in _warnings(cfg):
        print(f"aviso: {warning}")
    return 0


# ---------------------------------------------------------------- operação

def _control(cfg: Config, args, method: str, path: str, body: dict | None = None) -> dict:
    cert = Path(args.cert).resolve() if args.cert else cfg.operator_cert
    key = Path(args.key).resolve() if args.key else cfg.operator_key
    if cert is None or key is None:
        raise CliError("Informe o certificado do operador (--cert/--key ou [operator] na "
                       "configuração).")
    ctx = ssl.create_default_context(cafile=str(cfg.ca_file))
    ctx.minimum_version = ssl.TLSVersion.TLSv1_3
    try:
        ctx.load_cert_chain(str(cert), str(key),
                            password=lambda: getpass.getpass("Senha da chave do operador: "))
    except ssl.SSLError:
        raise CliError("Não foi possível carregar a chave do operador (senha incorreta?).") from None
    conn = http.client.HTTPSConnection("127.0.0.1", cfg.control_port, context=ctx, timeout=120)
    try:
        data = json.dumps(body).encode("utf-8") if body is not None else None
        headers = {"Content-Type": "application/json"} if data is not None else {}
        conn.request(method, path, body=data, headers=headers)
        resp = conn.getresponse()
        payload = json.loads(resp.read() or b"{}")
    except ConnectionRefusedError:
        raise CliError(f"Servidor não está rodando em 127.0.0.1:{cfg.control_port}.") from None
    except (OSError, ssl.SSLError, ValueError) as e:
        raise CliError(f"Falha ao falar com o servidor: {e}") from None
    finally:
        conn.close()
    if resp.status != 200:
        raise CliError(payload.get("error", f"HTTP {resp.status}"))
    return payload


def _print_status(st: dict) -> None:
    if st["sealed"]:
        print("Trancado.")
    else:
        print(f"Desbloqueado desde {st['unsealed_at']}: {st['entries']} segredo(s), "
              f"geração {st['generation']}.")


def cmd_unseal(args) -> int:
    cfg = load_config(args.config)
    password = getpass.getpass("Senha mestra do cofre: ")
    st = _control(cfg, args, "POST", "/v1/sys/unseal",
                  {"password": password, "accept_older": args.accept_older})
    del password
    _print_status(st)
    return 0


def cmd_seal(args) -> int:
    _print_status(_control(load_config(args.config), args, "POST", "/v1/sys/seal", {}))
    return 0


def cmd_status(args) -> int:
    _print_status(_control(load_config(args.config), args, "GET", "/v1/sys/status"))
    return 0


def cmd_audit_verify(args) -> int:
    path = Path(args.file) if args.file else load_config(args.config).audit_file
    count, problems = audit_mod.verify(path)
    for p in problems:
        print(p)
    print(f"{count} evento(s); {'cadeia íntegra' if not problems else f'{len(problems)} problema(s)'}.")
    return 1 if problems else 0


# ---------------------------------------------------------------- CA

def cmd_ca_init(args) -> int:
    pw = _new_secret("Nova senha da CA (mín. 12 caracteres): ")
    path = ca_mod.init_ca(Path(args.dir), args.name, pw)
    print(f"CA criada: {path}\nGuarde a pasta {args.dir} e a senha fora do servidor do cofre.")
    return 0


def cmd_ca_issue(args) -> int:
    ca_pw = getpass.getpass("Senha da CA: ")
    key_pw = None
    if args.kind == "operator" or args.key_password:
        key_pw = _new_secret("Senha para a nova chave (mín. 12 caracteres): ")
    issued = ca_mod.issue(Path(args.dir), args.kind, args.cn, ca_pw, Path(args.out),
                          sans=args.san or [], key_passphrase=key_pw, replace=args.replace,
                          days=args.days)
    print(f"Emitido ({args.kind}, série {issued.serial}):\n  {issued.cert_file}\n  {issued.key_file}")
    if args.replace:
        print("Certificados anteriores deste nome foram revogados: copie revoked.txt para o "
              "servidor.")
    return 0


def cmd_ca_revoke(args) -> int:
    item = ca_mod.revoke(Path(args.dir), args.serial)
    print(f"Revogado: {item['kind']} {item['cn']} (série {item['serial']}).\n"
          f"Copie {Path(args.dir) / 'revoked.txt'} para o servidor; ele relê o arquivo sozinho.")
    return 0


def cmd_ca_list(args) -> int:
    for i in ca_mod.list_issued(Path(args.dir)):
        state = f"REVOGADO em {i['revoked']}" if i.get("revoked") else f"válido até {i['not_after']}"
        print(f"{i['serial']}  {i['kind']:<8}  {i['cn']:<30}  {state}")
    return 0


# ---------------------------------------------------------------- parser

def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="python -m appvault_server",
                                description="App Vault Server: entrega segredos via mTLS.")
    p.add_argument("--version", action="version", version=__version__)
    sub = p.add_subparsers(dest="command", required=True)

    def with_config(sp):
        sp.add_argument("-c", "--config", required=True, help="arquivo server.toml")
        return sp

    def with_operator(sp):
        sp.add_argument("--cert", help="certificado do operador (padrão: [operator] da configuração)")
        sp.add_argument("--key", help="chave do operador")
        return sp

    with_config(sub.add_parser("serve", help="inicia o servidor")).set_defaults(func=cmd_serve)
    with_config(sub.add_parser("check", help="valida a configuração")).set_defaults(func=cmd_check)
    sp = with_operator(with_config(sub.add_parser("unseal", help="desbloqueia / recarrega o cofre")))
    sp.add_argument("--accept-older", action="store_true",
                    help="aceita um cofre anterior ao último publicado (restauração intencional)")
    sp.set_defaults(func=cmd_unseal)
    with_operator(with_config(sub.add_parser("seal", help="tranca"))).set_defaults(func=cmd_seal)
    with_operator(with_config(sub.add_parser("status", help="estado"))).set_defaults(func=cmd_status)
    sp = sub.add_parser("audit-verify", help="confere o log de auditoria")
    sp.add_argument("-c", "--config")
    sp.add_argument("--file", help="arquivo de log (em vez do configurado)")
    sp.set_defaults(func=cmd_audit_verify)

    ca = sub.add_parser("ca", help="CA interna").add_subparsers(dest="ca_command", required=True)
    sp = ca.add_parser("init", help="cria a CA")
    sp.add_argument("--dir", required=True)
    sp.add_argument("--name", default="App Vault Internal CA")
    sp.set_defaults(func=cmd_ca_init)
    sp = ca.add_parser("issue", help="emite um certificado")
    sp.add_argument("kind", choices=ca_mod.KINDS)
    sp.add_argument("--dir", required=True, help="pasta da CA")
    sp.add_argument("--cn", required=True,
                    help="servidor: nome DNS principal; cliente/operador: identidade da política")
    sp.add_argument("--out", required=True, help="pasta de saída do .pem/.key")
    sp.add_argument("--san", action="append", help="servidor: outro nome DNS ou IP (repetível)")
    sp.add_argument("--key-password", action="store_true",
                    help="cliente: protege a chave com senha (operador: sempre)")
    sp.add_argument("--replace", action="store_true", help="revoga os anteriores do mesmo nome")
    sp.add_argument("--days", type=int, default=ca_mod.LEAF_DAYS)
    sp.set_defaults(func=cmd_ca_issue)
    sp = ca.add_parser("revoke", help="revoga um certificado")
    sp.add_argument("--dir", required=True)
    sp.add_argument("--serial", required=True)
    sp.set_defaults(func=cmd_ca_revoke)
    sp = ca.add_parser("list", help="lista os certificados emitidos")
    sp.add_argument("--dir", required=True)
    sp.set_defaults(func=cmd_ca_list)
    return p


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    if args.command == "audit-verify" and not (args.config or args.file):
        print("erro: informe -c/--config ou --file", file=sys.stderr)
        return 2
    try:
        return args.func(args)
    except (CliError, ConfigError, PolicyError, ca_mod.CAError) as e:
        print(f"erro: {e}", file=sys.stderr)
        return 1
    except KeyboardInterrupt:
        return 130
