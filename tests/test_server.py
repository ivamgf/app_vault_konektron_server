import http.client
import json
import os
import shutil
import ssl
import sys
import tempfile
import unittest
from dataclasses import replace
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import appvault_server.server as server_mod  # noqa: E402
from appvault_client import (AccessDeniedError, AppVaultClient, AppVaultError,  # noqa: E402
                             NotFoundError, SealedError)
from appvault_server import audit, ca, cli  # noqa: E402
from appvault_server.config import Config, ConfigError, load_config  # noqa: E402
from appvault_server.policy import PolicyError, parse_policy  # noqa: E402
from vault import Entry, Vault  # noqa: E402

FAST_KDF = {"alg": "scrypt", "n": 2**14, "r": 8, "p": 1}
MASTER = "frase-senha mestra de teste 2026"
CA_PW = "senha da CA de teste"
OP_PW = "senha do operador teste"

POLICY = """
operators = ["op"]

[clients.sistema-x]
allow = [
  { environment = "produção", name = "banco siafe" },
  { environment = "Produção", name = "SFTP *" },
]

[clients.sistema-z]
allow = [{ environment = "*", name = "*" }]

[clients.sistema-y]
allow = []
"""


class ServerTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory()
        root = Path(cls.tmp.name)
        cls.ca_dir, certs = root / "ca", root / "certs"
        ca.init_ca(cls.ca_dir, "CA de teste", CA_PW)
        ca.issue(cls.ca_dir, "server", "cofre.test", CA_PW, certs)
        for cn in ("sistema-x", "sistema-y", "sistema-z"):
            ca.issue(cls.ca_dir, "client", cn, CA_PW, certs)
        ca.issue(cls.ca_dir, "operator", "op", CA_PW, certs, key_passphrase=OP_PW)
        other = root / "outra-ca"
        ca.init_ca(other, "CA intrusa", CA_PW)
        ca.issue(other, "client", "sistema-x", CA_PW, root / "intruso")
        cls.certs, cls.root = certs, root

        state = root / "state"
        state.mkdir()
        cls.vault_file = state / "cofre.db"
        with Vault.create(str(cls.vault_file), MASTER, kdf=FAST_KDF) as v:
            v.add(Entry("Banco SIAFE", "Produção", kind="database", host="db.interno",
                        port="5432", database="siafe", username="app", password="pw-prod",
                        extras=[{"key": "sslmode", "value": "require", "secret": False}]))
            v.add(Entry("SFTP dados", "Produção", kind="ftp", host="sftp", password="pw-sftp"))
            v.add(Entry("Banco SIAFE", "Homologação", kind="database", password="pw-hml"))
        (root / "policy.toml").write_text(POLICY, "utf-8")

        cls.cfg = Config(
            vault_file=cls.vault_file, state_dir=state, policy_file=root / "policy.toml",
            api_host="127.0.0.1", api_port=0, control_port=0,
            ca_file=cls.ca_dir / "ca.pem", cert_file=certs / "cofre.test.pem",
            key_file=certs / "cofre.test.key", revoked_file=cls.ca_dir / "revoked.txt",
            operator_cert=certs / "op.pem", operator_key=certs / "op.key")
        cls.delay = mock.patch.object(server_mod, "WRONG_PASSWORD_DELAY", 0)
        cls.delay.start()
        cls.app = server_mod.App(cls.cfg)
        cls.app.start()
        cls.url = f"https://127.0.0.1:{cls.app.api.server_port}"

    @classmethod
    def tearDownClass(cls):
        cls.app.stop()
        cls.delay.stop()
        cls.tmp.cleanup()

    def setUp(self):
        self.op("POST", "/v1/sys/seal", {})

    # ---- utilitários

    def client(self, cn="sistema-x", certs=None):
        certs = certs or self.certs
        return AppVaultClient(self.url, ca_file=str(self.cfg.ca_file),
                              cert_file=str(certs / f"{cn}.pem"),
                              key_file=str(certs / f"{cn}.key"), retries=0)

    def op(self, method, path, body=None, cn="op", password=OP_PW):
        ctx = ssl.create_default_context(cafile=str(self.cfg.ca_file))
        ctx.load_cert_chain(str(self.certs / f"{cn}.pem"), str(self.certs / f"{cn}.key"),
                            password=password)
        conn = http.client.HTTPSConnection("127.0.0.1", self.app.control.server_port,
                                           context=ctx, timeout=30)
        try:
            conn.request(method, path, body=json.dumps(body) if body is not None else None)
            resp = conn.getresponse()
            return resp.status, json.loads(resp.read())
        finally:
            conn.close()

    def unseal(self, password=MASTER, accept_older=False):
        return self.op("POST", "/v1/sys/unseal", {"password": password,
                                                  "accept_older": accept_older})

    # ---- testes

    def test_sealed_by_default(self):
        c = self.client()
        self.assertTrue(c.health()["sealed"])
        with self.assertRaises(SealedError):
            c.get("Produção", "Banco SIAFE")

    def test_wrong_master_password(self):
        status, body = self.unseal("senha errada mas comprida")
        self.assertEqual(status, 403)
        self.assertTrue(self.client().health()["sealed"])

    def test_read_allowed_secret(self):
        status, body = self.unseal()
        self.assertEqual(status, 200, body)
        self.assertEqual(body["entries"], 3)
        s = self.client().get("PRODUÇÃO", "banco siafe")
        self.assertEqual((s.host, s.password, s.extra("SSLMODE")), ("db.interno", "pw-prod", "require"))
        self.assertNotIn("pw-prod", repr(s))
        self.assertEqual(self.client().get("Produção", "SFTP dados").password, "pw-sftp")

    def test_policy_limits_access(self):
        self.unseal()
        c = self.client()
        with self.assertRaises(AccessDeniedError):
            c.get("Homologação", "Banco SIAFE")
        with self.assertRaises(NotFoundError):
            c.get("Produção", "SFTP inexistente")     # permitido pelo curinga, mas não existe
        self.assertEqual([(i["environment"], i["name"]) for i in c.list()],
                         [("Produção", "Banco SIAFE"), ("Produção", "SFTP dados")])
        with self.assertRaises(AccessDeniedError):
            self.client("sistema-y").get("Produção", "Banco SIAFE")

    def test_roles_are_separate(self):
        self.unseal()
        # cliente na porta de operação
        ctx = ssl.create_default_context(cafile=str(self.cfg.ca_file))
        ctx.load_cert_chain(str(self.certs / "sistema-x.pem"), str(self.certs / "sistema-x.key"))
        conn = http.client.HTTPSConnection("127.0.0.1", self.app.control.server_port, context=ctx)
        conn.request("POST", "/v1/sys/seal", body="{}")
        self.assertEqual(conn.getresponse().status, 403)
        conn.close()
        # operador na API
        op = AppVaultClient(self.url, ca_file=str(self.cfg.ca_file),
                            cert_file=str(self.certs / "op.pem"),
                            key_file=str(self.certs / "op.key"), key_password=OP_PW, retries=0)
        with self.assertRaises(AccessDeniedError):
            op.get("Produção", "Banco SIAFE")
        self.assertFalse(self.client().health()["sealed"])

    def test_foreign_ca_rejected(self):
        with self.assertRaises(AppVaultError):
            self.client(certs=self.root / "intruso").health()

    def test_revoked_certificate(self):
        self.unseal()
        z = self.client("sistema-z")
        self.assertEqual(z.get("Homologação", "Banco SIAFE").password, "pw-hml")
        serial = next(i["serial"] for i in ca.list_issued(self.ca_dir) if i["cn"] == "sistema-z")
        ca.revoke(self.ca_dir, serial)
        with self.assertRaises(AccessDeniedError):
            z.get("Homologação", "Banco SIAFE")
        self.assertEqual(self.client().get("Produção", "Banco SIAFE").host, "db.interno")

    def test_broken_policy_denies_everything(self):
        self.unseal()
        path = self.cfg.policy_file
        try:
            path.write_text("operators = 'não é lista'", "utf-8")
            with self.assertRaises(SealedError):        # 503: política indisponível
                self.client().get("Produção", "Banco SIAFE")
        finally:
            path.write_text(POLICY + "\n", "utf-8")
        self.assertEqual(self.client().get("Produção", "Banco SIAFE").host, "db.interno")

    def test_republish_and_rollback_protection(self):
        self.assertEqual(self.unseal()[0], 200)
        old = self.root / "cofre-antigo.db"
        shutil.copyfile(self.vault_file, old)
        with Vault.open(str(self.vault_file), MASTER) as v:
            e = v.get("Produção", "Banco SIAFE")
            e.password = "pw-nova"
            v.update("Produção", "Banco SIAFE", e)
        status, body = self.unseal()                     # republicação = novo unseal
        self.assertEqual(status, 200)
        self.assertEqual(self.client().get("Produção", "Banco SIAFE").password, "pw-nova")

        newest = self.root / "cofre-novo.db"
        shutil.copyfile(self.vault_file, newest)
        shutil.copyfile(old, self.vault_file)            # alguém publica o arquivo antigo
        try:
            status, body = self.unseal()
            self.assertEqual(status, 409, body)
            # continua servindo a versão nova que já estava na memória
            self.assertEqual(self.client().get("Produção", "Banco SIAFE").password, "pw-nova")
            self.assertEqual(self.unseal(accept_older=True)[0], 200)
            self.assertEqual(self.client().get("Produção", "Banco SIAFE").password, "pw-prod")
        finally:
            shutil.copyfile(newest, self.vault_file)
            self.assertEqual(self.unseal()[0], 200)

    def test_cli_unseal_and_status(self):
        cfg = replace(self.cfg, control_port=self.app.control.server_port)
        args = SimpleNamespace(cert=None, key=None, accept_older=False)
        with mock.patch.object(cli, "load_config", return_value=cfg), \
                mock.patch.object(cli.getpass, "getpass", side_effect=[MASTER, OP_PW]):
            self.assertEqual(cli.cmd_unseal(SimpleNamespace(config="x", **vars(args))), 0)
        with mock.patch.object(cli.getpass, "getpass", return_value=OP_PW):
            st = cli._control(cfg, args, "GET", "/v1/sys/status")
        self.assertFalse(st["sealed"])

    def test_audit_log(self):
        self.unseal()
        self.client().get("Produção", "Banco SIAFE")
        with self.assertRaises(AccessDeniedError):
            self.client().get("Homologação", "Banco SIAFE")
        text = self.cfg.audit_file.read_text("utf-8")
        events = [json.loads(line)["event"] for line in text.splitlines()]
        self.assertIn("read", events)
        self.assertIn("read_denied", events)
        for secret in ("pw-prod", "pw-hml", "pw-sftp", MASTER):
            self.assertNotIn(secret, text)
        count, problems = audit.verify(self.cfg.audit_file)
        self.assertEqual(problems, [])

        copy = self.root / "audit-adulterado.log"
        lines = text.splitlines()
        lines[1] = lines[1].replace('"event":"', '"event":"x', 1)
        del lines[3]
        copy.write_text("\n".join(lines) + "\n", "utf-8")
        _, problems = audit.verify(copy)
        self.assertTrue(any("alterado" in p for p in problems))
        self.assertTrue(any("anterior" in p for p in problems))


class PolicyTest(unittest.TestCase):
    def test_validation(self):
        bad = [
            {"operators": "op"},
            {"operators": ["com espaço"]},
            {"operators": ["a"], "clients": {"a": {"allow": []}}},
            {"clients": {"x": {"allow": [{"environment": "P"}]}}},
            {"clients": {"x": {"deny": []}}},
            {"extra": 1},
        ]
        for data in bad:
            with self.assertRaises(PolicyError, msg=data):
                parse_policy(data)

    def test_matching(self):
        p = parse_policy({"clients": {"x": {"allow": [
            {"environment": "Produção", "name": "API *"}]}}})
        self.assertTrue(p.can_read("x", "PRODUÇÃO", "api ibge"))
        self.assertFalse(p.can_read("x", "Homologação", "API IBGE"))
        self.assertFalse(p.can_read("y", "Produção", "API IBGE"))


class CATest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.dir = Path(self.tmp.name) / "ca"
        ca.init_ca(self.dir, "CA", CA_PW)

    def tearDown(self):
        self.tmp.cleanup()

    def test_rules(self):
        out = Path(self.tmp.name) / "out"
        with self.assertRaises(ca.CAError):
            ca.init_ca(self.dir, "CA", CA_PW)                     # já existe
        with self.assertRaises(ca.CAError):
            ca.issue(self.dir, "client", "x", "senha errada da CA", out)
        with self.assertRaises(ca.CAError):
            ca.issue(self.dir, "operator", "op", CA_PW, out)      # sem senha na chave
        with self.assertRaises(ca.CAError):
            ca.issue(self.dir, "client", "nome inválido", CA_PW, out)
        first = ca.issue(self.dir, "client", "x", CA_PW, out)
        with self.assertRaises(ca.CAError):
            ca.issue(self.dir, "client", "x", CA_PW, out / "2")   # já há um ativo
        second = ca.issue(self.dir, "client", "x", CA_PW, out / "2", replace=True)
        revoked = (self.dir / "revoked.txt").read_text().split()
        self.assertEqual(revoked, [first.serial])
        self.assertNotIn(second.serial, revoked)
        if os.name != "nt":
            self.assertEqual(os.stat(first.key_file).st_mode & 0o777, 0o600)

    def test_config_paths_are_relative_to_file(self):
        cfg_file = Path(self.tmp.name) / "server.toml"
        cfg_file.write_text('vault_file = "cofre.db"\nstate_dir = "estado"\n'
                            'policy_file = "policy.toml"\n'
                            '[tls]\nca = "ca.pem"\ncert = "s.pem"\nkey = "s.key"\n', "utf-8")
        cfg = load_config(cfg_file)
        self.assertEqual(cfg.vault_file, (Path(self.tmp.name) / "cofre.db").resolve())
        self.assertEqual((cfg.api_port, cfg.control_port), (8443, 8444))
        cfg_file.write_text('vault_file = "x"\n[api]\nport = 99999\n', "utf-8")
        with self.assertRaises(ConfigError):
            load_config(cfg_file)


if __name__ == "__main__":
    unittest.main()
