"""
CA interna: emite os certificados do servidor, dos sistemas (clientes) e dos operadores.

Pasta da CA (guarde fora do servidor do cofre, de preferência numa máquina offline)::

    ca.key       chave privada da CA, sempre criptografada com senha
    ca.pem       certificado da CA (vai para o servidor e para os clientes)
    index.json   certificados emitidos
    revoked.txt  números de série revogados (copie para o servidor após revogar)

Chaves ECDSA P-256. A chave do servidor e a do cliente ficam sem senha, porque o
serviço precisa iniciar sozinho: proteja-as com permissão de arquivo. A do operador
sempre tem senha.
"""
from __future__ import annotations

import ipaddress
import json
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

from .files import write_atomic, write_new
from .policy import CN_RE

KINDS = ("server", "client", "operator")
MIN_PASSPHRASE_LEN = 12
CA_DAYS = 3650
LEAF_DAYS = 397      # pouco mais de um ano: obriga a renovar e rever acessos


class CAError(Exception):
    pass


@dataclass(frozen=True)
class Issued:
    cert_file: Path
    key_file: Path
    serial: str


def _check_passphrase(value: str, what: str) -> bytes:
    if len(value) < MIN_PASSPHRASE_LEN:
        raise CAError(f"A senha {what} precisa de pelo menos {MIN_PASSPHRASE_LEN} caracteres.")
    return value.encode("utf-8")


def _serial_hex(serial: int) -> str:
    # Mesmo formato do ssl.getpeercert()["serialNumber"].
    text = f"{serial:X}"
    return text if len(text) % 2 == 0 else "0" + text


def _key_pem(key: ec.EllipticCurvePrivateKey, passphrase: bytes | None) -> bytes:
    enc = (serialization.BestAvailableEncryption(passphrase) if passphrase
           else serialization.NoEncryption())
    return key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, enc)


def _name(cn: str, org: str | None = None) -> x509.Name:
    attrs = [x509.NameAttribute(NameOID.COMMON_NAME, cn)]
    if org:
        attrs.append(x509.NameAttribute(NameOID.ORGANIZATION_NAME, org))
    return x509.Name(attrs)


def _index(ca_dir: Path) -> list[dict]:
    try:
        return json.loads((ca_dir / "index.json").read_text("utf-8"))
    except FileNotFoundError:
        return []


def _save_index(ca_dir: Path, index: list[dict]) -> None:
    write_atomic(ca_dir / "index.json",
                 json.dumps(index, ensure_ascii=False, indent=2).encode("utf-8"))


def _save_revoked(ca_dir: Path, index: list[dict]) -> None:
    lines = [i["serial"] for i in index if i.get("revoked")]
    write_atomic(ca_dir / "revoked.txt", ("\n".join(lines) + "\n" if lines else "").encode())


def init_ca(ca_dir: Path, name: str, passphrase: str) -> Path:
    ca_dir.mkdir(parents=True, exist_ok=True)
    if (ca_dir / "ca.key").exists() or (ca_dir / "ca.pem").exists():
        raise CAError(f"Já existe uma CA em {ca_dir}.")
    pw = _check_passphrase(passphrase, "da CA")
    key = ec.generate_private_key(ec.SECP256R1())
    now = datetime.now(timezone.utc)
    subject = _name(name)
    cert = (x509.CertificateBuilder()
            .subject_name(subject).issuer_name(subject)
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - timedelta(minutes=5))
            .not_valid_after(now + timedelta(days=CA_DAYS))
            .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
            .add_extension(x509.KeyUsage(digital_signature=False, content_commitment=False,
                                         key_encipherment=False, data_encipherment=False,
                                         key_agreement=False, key_cert_sign=True, crl_sign=True,
                                         encipher_only=False, decipher_only=False), critical=True)
            .add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()),
                           critical=False)
            .sign(key, hashes.SHA256()))
    write_new(ca_dir / "ca.key", _key_pem(key, pw), private=True)
    write_new(ca_dir / "ca.pem", cert.public_bytes(serialization.Encoding.PEM))
    _save_index(ca_dir, [])
    _save_revoked(ca_dir, [])
    return ca_dir / "ca.pem"


def _load_ca(ca_dir: Path, passphrase: str):
    try:
        cert = x509.load_pem_x509_certificate((ca_dir / "ca.pem").read_bytes())
        key_pem = (ca_dir / "ca.key").read_bytes()
    except FileNotFoundError:
        raise CAError(f"CA não encontrada em {ca_dir}. Use 'ca init' primeiro.") from None
    try:
        key = serialization.load_pem_private_key(key_pem, passphrase.encode("utf-8"))
    except (ValueError, TypeError):
        raise CAError("Senha da CA incorreta.") from None
    return cert, key


def issue(ca_dir: Path, kind: str, cn: str, ca_passphrase: str, out_dir: Path,
          sans: list[str] | tuple[str, ...] = (), key_passphrase: str | None = None,
          replace: bool = False, days: int = LEAF_DAYS) -> Issued:
    """Emite um certificado. replace=True revoga os anteriores do mesmo CN e tipo."""
    if kind not in KINDS:
        raise CAError(f"Tipo inválido: {kind} (use {', '.join(KINDS)}).")
    if not CN_RE.match(cn):
        raise CAError("Nome inválido: use letras, números, ponto, hífen e sublinhado.")
    if kind == "operator" and not key_passphrase:
        raise CAError("A chave do operador precisa de senha.")
    if not 1 <= days <= 825:
        raise CAError("Validade deve ficar entre 1 e 825 dias.")
    kpw = _check_passphrase(key_passphrase, "da chave") if key_passphrase else None

    ca_cert, ca_key = _load_ca(ca_dir, ca_passphrase)
    index = _index(ca_dir)
    active = [i for i in index if i["cn"] == cn and i["kind"] == kind and not i.get("revoked")]
    if active and not replace:
        raise CAError(f"Já existe um certificado {kind} ativo para {cn}. "
                      "Use --replace para emitir outro e revogar o anterior.")

    out_dir.mkdir(parents=True, exist_ok=True)
    cert_file, key_file = out_dir / f"{cn}.pem", out_dir / f"{cn}.key"
    for f in (cert_file, key_file):
        if f.exists():
            raise CAError(f"{f} já existe; mova ou apague antes de emitir.")

    key = ec.generate_private_key(ec.SECP256R1())
    now = datetime.now(timezone.utc)
    serial = x509.random_serial_number()
    not_after = min(now + timedelta(days=days), ca_cert.not_valid_after_utc)
    usage = ExtendedKeyUsageOID.SERVER_AUTH if kind == "server" else ExtendedKeyUsageOID.CLIENT_AUTH
    builder = (x509.CertificateBuilder()
               .subject_name(_name(cn)).issuer_name(ca_cert.subject)
               .public_key(key.public_key())
               .serial_number(serial)
               .not_valid_before(now - timedelta(minutes=5))
               .not_valid_after(not_after)
               .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
               .add_extension(x509.KeyUsage(digital_signature=True, content_commitment=False,
                                            key_encipherment=False, data_encipherment=False,
                                            key_agreement=False, key_cert_sign=False,
                                            crl_sign=False, encipher_only=False,
                                            decipher_only=False), critical=True)
               .add_extension(x509.ExtendedKeyUsage([usage]), critical=False)
               .add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()),
                              critical=False)
               .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(
                   ca_key.public_key()), critical=False))
    if kind == "server":
        names: list[x509.GeneralName] = []
        # localhost/127.0.0.1 sempre: é por onde o operador desbloqueia o servidor.
        for san in [cn, *sans, "localhost", "127.0.0.1"]:
            try:
                gn = x509.IPAddress(ipaddress.ip_address(san))
            except ValueError:
                gn = x509.DNSName(san)
            if gn not in names:
                names.append(gn)
        builder = builder.add_extension(x509.SubjectAlternativeName(names), critical=False)
    cert = builder.sign(ca_key, hashes.SHA256())

    write_new(key_file, _key_pem(key, kpw), private=True)
    write_new(cert_file, cert.public_bytes(serialization.Encoding.PEM))

    serial_hex = _serial_hex(serial)
    for i in active:
        i["revoked"] = now.isoformat(timespec="seconds")
    index.append({"serial": serial_hex, "kind": kind, "cn": cn,
                  "issued": now.isoformat(timespec="seconds"),
                  "not_after": not_after.isoformat(timespec="seconds")})
    _save_index(ca_dir, index)
    if active:
        _save_revoked(ca_dir, index)
    return Issued(cert_file, key_file, serial_hex)


def revoke(ca_dir: Path, serial: str) -> dict:
    serial = serial.strip().upper().removeprefix("0X")
    index = _index(ca_dir)
    for item in index:
        if item["serial"].lstrip("0") == serial.lstrip("0"):
            if item.get("revoked"):
                raise CAError(f"{serial} já estava revogado.")
            item["revoked"] = datetime.now(timezone.utc).isoformat(timespec="seconds")
            _save_index(ca_dir, index)
            _save_revoked(ca_dir, index)
            return item
    raise CAError(f"Série não encontrada no índice: {serial}")


def list_issued(ca_dir: Path) -> list[dict]:
    return _index(ca_dir)
