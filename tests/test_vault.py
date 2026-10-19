import json
import os
import sqlite3
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from vault import (Entry, EntryExistsError, EntryNotFoundError, IntegrityError, Vault,
                   VaultError, WrongPasswordError, generate_password)

FAST_KDF = {"alg": "scrypt", "n": 2**14, "r": 8, "p": 1}
MASTER = "frase-senha mestra de teste 2026"


class VaultTest(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.TemporaryDirectory()
        self.path = os.path.join(self.dir.name, "cofre.db")
        self.v = Vault.create(self.path, MASTER, kdf=FAST_KDF)
        self.v.add(Entry("SFTP dados", "Produção", kind="ftp", host="sftp.exemplo.gov",
                         port="22", username="etl", password="p@ss-prod"))
        self.v.add(Entry("SFTP dados", "Homologação", kind="ftp", host="sftp-hml.exemplo.gov",
                         username="etl", password="p@ss-hml"))
        self.v.add(Entry("API IBGE", "Produção", kind="api", url="https://api.exemplo",
                         token="tok-123", extras=[{"key": "tenant", "value": "x", "secret": False}]))

    def tearDown(self):
        if self.v._conn is not None:
            self.v.close()
        self.dir.cleanup()

    def reopen(self, password=MASTER):
        self.v.close()
        self.v = Vault.open(self.path, password)
        return self.v

    def raw(self):
        return sqlite3.connect(self.path, isolation_level=None)

    # ---- básico

    def test_roundtrip_and_environments(self):
        v = self.reopen()
        self.assertEqual(v.get("produção", "sftp dados").password, "p@ss-prod")
        self.assertEqual(v.get("Homologação", "SFTP dados").password, "p@ss-hml")
        self.assertEqual([e.name for e in v.list_entries("Produção")], ["API IBGE", "SFTP dados"])
        self.assertEqual(v.get("Produção", "API IBGE").extras[0]["key"], "tenant")

    def test_names_not_in_plaintext(self):
        self.v.close()
        with open(self.path, "rb") as f:
            data = f.read()
        for needle in ("SFTP", "Produção", "sftp.exemplo", "p@ss", "tok-123"):
            self.assertNotIn(needle.encode("utf-8"), data)

    def test_duplicate_is_rejected_case_insensitive(self):
        with self.assertRaises(EntryExistsError):
            self.v.add(Entry("sftp DADOS", "produção", kind="ftp"))

    def test_update_moves_between_environments(self):
        e = self.v.get("Produção", "API IBGE")
        e.environment, e.token = "Desenvolvimento", "tok-dev"
        saved = self.v.update("Produção", "API IBGE", e)
        self.assertEqual(saved.created_at, e.created_at)
        with self.assertRaises(EntryNotFoundError):
            self.v.get("Produção", "API IBGE")
        self.assertEqual(self.reopen().get("Desenvolvimento", "API IBGE").token, "tok-dev")

    def test_update_cannot_overwrite_other(self):
        e = self.v.get("Homologação", "SFTP dados")
        e.environment = "Produção"
        with self.assertRaises(EntryExistsError):
            self.v.update("Homologação", "SFTP dados", e)

    def test_delete(self):
        self.v.delete("Produção", "API IBGE")
        with self.assertRaises(EntryNotFoundError):
            self.reopen().get("Produção", "API IBGE")

    def test_environment_management(self):
        self.v.add_environment("Cliente X")
        with self.assertRaises(VaultError):
            self.v.add_environment("cliente x")
        self.v.rename_environment("Homologação", "Staging")
        v = self.reopen()
        self.assertEqual(v.get("Staging", "SFTP dados").password, "p@ss-hml")
        with self.assertRaises(VaultError):
            v.delete_environment("Staging")       # ainda tem segredos
        v.delete_environment("Cliente X")
        self.assertEqual(v.environments(), ["Produção", "Staging", "Desenvolvimento"])

    def test_validation(self):
        with self.assertRaises(VaultError):
            self.v.add(Entry("x", "Inexistente"))
        with self.assertRaises(VaultError):
            self.v.add(Entry("x", "Produção", port="99999"))
        with self.assertRaises(VaultError):
            self.v.add(Entry("nome‮invisível", "Produção"))
        with self.assertRaises(VaultError):
            self.v.add(Entry("x", "Produção", kind="desconhecido"))

    # ---- senha mestra

    def test_wrong_password(self):
        self.v.close()
        with self.assertRaises(WrongPasswordError):
            Vault.open(self.path, "senha errada mas longa")
        self.v = Vault.open(self.path, MASTER)

    def test_change_password_rotates_dek(self):
        conn = self.raw()
        old_rows = conn.execute("SELECT id FROM entries ORDER BY id").fetchall()
        conn.close()
        self.v.change_master_password(MASTER, "nova frase-senha bem longa")
        conn = self.raw()
        new_rows = conn.execute("SELECT id FROM entries ORDER BY id").fetchall()
        conn.close()
        self.assertNotEqual(old_rows, new_rows)  # IDs mudam: nova chave de índice
        self.assertEqual(self.v.get("Produção", "SFTP dados").password, "p@ss-prod")
        with self.assertRaises(WrongPasswordError):
            self.reopen()
        v = Vault.open(self.path, "nova frase-senha bem longa")
        self.v = v
        self.assertEqual(v.get("Homologação", "SFTP dados").password, "p@ss-hml")

    def test_weak_master_password(self):
        with self.assertRaises(VaultError):
            Vault.create(os.path.join(self.dir.name, "x.db"), "curta", kdf=FAST_KDF)
        with self.assertRaises(VaultError):
            Vault.create(os.path.join(self.dir.name, "y.db"), "aaaaaaaaaaaaaaaa", kdf=FAST_KDF)
        self.assertFalse(os.path.exists(os.path.join(self.dir.name, "x.db")))

    def test_stale_instance_after_password_change(self):
        other = Vault.open(self.path, MASTER)
        try:
            self.v.change_master_password(MASTER, "nova frase-senha bem longa")
            with self.assertRaises(VaultError):
                other.add(Entry("x", "Produção"))
        finally:
            other.close()
        Vault.open(self.path, "nova frase-senha bem longa").close()

    # ---- adulteração do arquivo

    def test_tampered_kdf_header(self):
        self.v.close()
        conn = self.raw()
        conn.execute("UPDATE meta SET value = ? WHERE key = 'kdf'",
                     (json.dumps({"alg": "scrypt", "n": 2**15, "p": 1, "r": 8}, sort_keys=True),))
        conn.close()
        with self.assertRaises(WrongPasswordError):
            self.v = Vault.open(self.path, MASTER)

    def test_absurd_kdf_rejected(self):
        self.v.close()
        conn = self.raw()
        conn.execute("UPDATE meta SET value = ? WHERE key = 'kdf'",
                     (json.dumps({"alg": "scrypt", "n": 2**30, "p": 1, "r": 8}),))
        conn.close()
        with self.assertRaises(VaultError):
            self.v = Vault.open(self.path, MASTER)

    def test_swapped_rows_detected(self):
        self.v.close()
        conn = self.raw()
        (a, na, ca), (b, nb, cb) = conn.execute("SELECT id, nonce, ciphertext FROM entries LIMIT 2")
        conn.execute("UPDATE entries SET nonce = ?, ciphertext = ? WHERE id = ?", (nb, cb, a))
        conn.execute("UPDATE entries SET nonce = ?, ciphertext = ? WHERE id = ?", (na, ca, b))
        conn.close()
        with self.assertRaises(IntegrityError):
            self.v = Vault.open(self.path, MASTER)

    def test_deleted_row_detected(self):
        self.v.close()
        conn = self.raw()
        conn.execute("DELETE FROM entries WHERE rowid = (SELECT MIN(rowid) FROM entries)")
        conn.close()
        with self.assertRaises(IntegrityError):
            self.v = Vault.open(self.path, MASTER)

    def test_rolled_back_row_detected(self):
        conn = self.raw()
        old = conn.execute("SELECT id, nonce, ciphertext FROM entries").fetchall()
        conn.close()
        e = self.v.get("Produção", "SFTP dados")
        e.password = "senha-nova"
        self.v.update("Produção", "SFTP dados", e)
        self.v.close()
        conn = self.raw()
        conn.execute("DELETE FROM entries")
        conn.executemany("INSERT INTO entries VALUES (?, ?, ?)", old)
        conn.close()
        with self.assertRaises(IntegrityError):
            self.v = Vault.open(self.path, MASTER)

    def test_not_a_vault(self):
        other = os.path.join(self.dir.name, "outro.db")
        with open(other, "wb") as f:
            f.write(b"isso nao e um banco sqlite" * 100)
        with self.assertRaises(VaultError):
            Vault.open(other, MASTER)

    # ---- contador de geração

    def test_generation_increases_on_every_write(self):
        g = self.v.generation          # create + 3 adds
        self.assertEqual(g, 4)
        cid = self.v.content_id
        self.v.add_environment("Cliente X")
        self.v.change_master_password(MASTER, "nova frase-senha bem longa")
        self.assertEqual(self.v.generation, g + 2)
        self.assertNotEqual(self.v.content_id, cid)
        dest = os.path.join(self.dir.name, "backup.db")
        self.v.backup(dest)
        with Vault.open(dest, "nova frase-senha bem longa") as b:
            self.assertEqual((b.generation, b.content_id), (self.v.generation, self.v.content_id))

    def test_tampered_generation_detected(self):
        self.v.close()
        conn = self.raw()
        conn.execute("UPDATE meta SET value = 99 WHERE key = 'generation'")
        conn.close()
        with self.assertRaises(IntegrityError):
            self.v = Vault.open(self.path, MASTER)

    def test_removed_generation_detected(self):
        self.v.close()
        conn = self.raw()
        conn.execute("DELETE FROM meta WHERE key = 'generation'")
        conn.close()
        with self.assertRaises(IntegrityError):
            self.v = Vault.open(self.path, MASTER)

    def test_vault_without_generation_opens_as_zero(self):
        # Simula um cofre gravado antes do contador existir.
        self.v._conn.execute("DELETE FROM meta WHERE key = 'generation'")
        self.v._write_manifest()
        v = self.reopen()
        self.assertEqual(v.generation, 0)
        v.add_environment("Cliente X")
        self.assertEqual(self.reopen().generation, 1)

    # ---- utilitários

    def test_backup(self):
        dest = os.path.join(self.dir.name, "backup.db")
        self.v.backup(dest)
        with self.assertRaises(VaultError):
            self.v.backup(dest)
        with self.assertRaises(VaultError):
            self.v.backup(self.path, overwrite=True)
        with Vault.open(dest, MASTER) as b:
            self.assertEqual(b.get("Produção", "API IBGE").token, "tok-123")

    def test_create_refuses_existing_file(self):
        with self.assertRaises(VaultError):
            Vault.create(self.path, MASTER, kdf=FAST_KDF)

    def test_generate_password(self):
        for _ in range(50):
            pw = generate_password(12)
            self.assertEqual(len(pw), 12)
            self.assertTrue(any(c.islower() for c in pw) and any(c.isupper() for c in pw)
                            and any(c.isdigit() for c in pw)
                            and any(not c.isalnum() for c in pw))
        self.assertTrue(generate_password(16, symbols=False).isalnum())


if __name__ == "__main__":
    unittest.main()
