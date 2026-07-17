"""PAdES certification signing for Lifted Sign executed documents.

This is the REAL cryptographic lock that replaces the advisory AES-empty-password
"seal": a PAdES (ETSI.CAdES.detached) *certification* signature applied at DocMDP
level 1 (``MDPPerm.NO_CHANGES``). Any modification of the document after
certification — a one-byte content edit or a whole incremental revision appended
after the fact — invalidates the signature in every compliant PDF viewer
(Adobe Acrobat et al.), exactly the DocuSign / Dropbox Sign "certified copy" model.

Dependency stack is fully permissive (MIT): pyHanko + pyhanko-certvalidator +
asn1crypto + oscrypto; self-signed cert generation uses ``cryptography``
(Apache/BSD). No AGPL anywhere on this path.

KEY HYGIENE (non-negotiable — a leaked signing key forges unlimited certifications):
  * This module NEVER writes a private key anywhere under the git worktree.
  * Callers pass PEM bytes/str loaded at runtime from the environment
    (``SIGN_PADES_CERT_PEM`` / ``_KEY_PEM``) or a gitignored path outside the repo
    (``SIGN_PADES_CERT_PATH`` / ``_KEY_PATH``) — the key is never a literal here.
  * The ``provision`` CLI refuses to write under the repo root.

Public surface:
  generate_self_signed(common_name, org, days) -> (cert_pem, key_pem)
  material_ok(cert_pem, key_pem, passphrase) -> bool        # cheap parse/validity gate
  certify_pdf(pdf_bytes, cert_pem, key_pem, reason, ...) -> signed bytes
  validate(signed_bytes, cert_pem=None) -> {valid, certified, tampered, ...}
"""

from __future__ import annotations

import datetime
import io

# --- self-signed cert generation (cryptography only) --------------------------
from cryptography import x509 as cx509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

from . import config

# Identity that names this cert/signature. Env-derived (blank by default);
# falls back to the product display name so a self-signed cert always has a
# non-empty subject — never a hardcoded company literal.
_DEFAULT_IDENTITY = config.LEGAL_ENTITY or "Lifted Sign"

_DER = serialization.Encoding.DER
_PEM = serialization.Encoding.PEM
_PKCS8 = serialization.PrivateFormat.PKCS8


def _as_bytes(v: bytes | str) -> bytes:
    return v.encode("utf-8") if isinstance(v, str) else v


def generate_self_signed(
    common_name: str | None = None,
    org: str | None = None,
    days: int = 3650,
) -> tuple[bytes, bytes]:
    """Return (cert_pem, key_pem) for a self-signed signing cert.

    RSA-2048, SHA-256, KeyUsage(digital_signature, content_commitment, key_cert_sign),
    BasicConstraints CA=True (self-issued root that signs itself). Uses ``cryptography``
    only. NEVER writes to the repo — the caller decides where (if anywhere) the key lands.

    ``common_name``/``org`` default to the configured legal entity (``config.LEGAL_ENTITY``),
    falling back to the product display name when unset — no hardcoded company literal.
    """
    common_name = common_name or _DEFAULT_IDENTITY
    org = org or _DEFAULT_IDENTITY
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = cx509.Name(
        [
            cx509.NameAttribute(NameOID.COMMON_NAME, common_name),
            cx509.NameAttribute(NameOID.ORGANIZATION_NAME, org),
        ]
    )
    now = datetime.datetime.now(datetime.timezone.utc)
    cert = (
        cx509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(cx509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(days=1))
        .not_valid_after(now + datetime.timedelta(days=max(1, days)))
        .add_extension(cx509.BasicConstraints(ca=True, path_length=None), critical=True)
        .add_extension(
            cx509.KeyUsage(
                digital_signature=True,
                content_commitment=True,  # a.k.a. non-repudiation
                key_cert_sign=True,  # self-signs its own cert
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                crl_sign=False,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .sign(key, hashes.SHA256())
    )
    cert_pem = cert.public_bytes(_PEM)
    key_pem = key.private_bytes(_PEM, _PKCS8, serialization.NoEncryption())
    return cert_pem, key_pem


def _load_pair(cert_pem: bytes | str, key_pem: bytes | str, key_passphrase: bytes | None):
    """Parse PEM cert + key with ``cryptography``. Raises on bad material."""
    cert = cx509.load_pem_x509_certificate(_as_bytes(cert_pem))
    key = serialization.load_pem_private_key(_as_bytes(key_pem), password=key_passphrase)
    return cert, key


def material_ok(
    cert_pem: bytes | str | None,
    key_pem: bytes | str | None,
    key_passphrase: bytes | None = None,
) -> bool:
    """Cheap up-front gate: cert + key parse, key matches cert, cert not expired.

    Used by finalize() to decide the seal method BEFORE rendering the certificate page,
    so the cert wording is truthful and the sign path is only entered when it will work.
    Returns False (never raises) on any problem.
    """
    if not cert_pem or not key_pem:
        return False
    try:
        cert, key = _load_pair(cert_pem, key_pem, key_passphrase)
        # key must correspond to the cert
        if key.public_key().public_numbers() != cert.public_key().public_numbers():
            return False
        # cert must be currently valid (not expired / not yet valid)
        now = datetime.datetime.now(datetime.timezone.utc)
        if now < cert.not_valid_before_utc or now > cert.not_valid_after_utc:
            return False
        return True
    except Exception:
        return False


def _signer(cert, key):
    """Build a pyHanko SimpleSigner from in-memory cryptography objects.

    (SimpleSigner.load wants file paths — we never touch disk, so construct directly.)
    """
    from asn1crypto import keys as akeys
    from asn1crypto import x509 as ax509
    from pyhanko.sign.signers import SimpleSigner
    from pyhanko_certvalidator.registry import SimpleCertificateStore

    return SimpleSigner(
        signing_cert=ax509.Certificate.load(cert.public_bytes(_DER)),
        signing_key=akeys.PrivateKeyInfo.load(
            key.private_bytes(_DER, _PKCS8, serialization.NoEncryption())
        ),
        cert_registry=SimpleCertificateStore(),
    )


def certify_pdf(
    pdf_bytes: bytes,
    cert_pem: bytes | str,
    key_pem: bytes | str,
    reason: str = "Certified executed copy — no changes permitted after certification",
    *,
    key_passphrase: bytes | None = None,
    field_name: str = "LiftedCertification",
    location: str | None = None,
    signer_name: str | None = None,
) -> bytes:
    """Apply a PAdES (ETSI.CAdES.detached) certification signature at DocMDP level 1
    (NO_CHANGES). Returns the signed PDF bytes.

    MUST be the final byte operation on the document — any later scrub / subset /
    tobytes / append / encrypt re-serializes the file and silently invalidates the
    signature (the byte-range no longer covers the delivered bytes). An invisible
    signature field is auto-created; the human-visible evidence is the separate
    Certificate-of-Completion page.

    ``location``/``signer_name`` default to the configured legal entity
    (``config.LEGAL_ENTITY``), falling back to the product display name — no
    hardcoded company literal.
    """
    location = location or _DEFAULT_IDENTITY
    signer_name = signer_name or _DEFAULT_IDENTITY
    from pyhanko.pdf_utils.incremental_writer import IncrementalPdfFileWriter
    from pyhanko.sign.fields import MDPPerm, SigSeedSubFilter
    from pyhanko.sign.signers import PdfSignatureMetadata, PdfSigner

    cert, key = _load_pair(cert_pem, key_pem, key_passphrase)
    signer = _signer(cert, key)
    meta = PdfSignatureMetadata(
        field_name=field_name,
        certify=True,
        docmdp_permissions=MDPPerm.NO_CHANGES,  # DocMDP level 1 — no changes allowed
        subfilter=SigSeedSubFilter.PADES,
        reason=reason,
        location=location,
        name=signer_name,
    )
    out = io.BytesIO()
    PdfSigner(meta, signer=signer).sign_pdf(
        IncrementalPdfFileWriter(io.BytesIO(pdf_bytes)), output=out
    )
    return out.getvalue()


def validate(
    signed_bytes: bytes,
    cert_pem: bytes | str | None = None,
) -> dict:
    """Validate a certified PDF.

    Returns::

        {'valid': bool, 'certified': bool, 'tampered': bool, 'docmdp_ok': bool,
         'coverage': str, 'modification_level': str, 'signer': str, 'reason': str}

    Semantics:
      * valid     = status.bottom_line (intact + trusted + docmdp_ok)
      * certified = read_certification_data(reader).permission == MDPPerm.NO_CHANGES
      * tampered  = (not status.intact) or (not status.docmdp_ok)
                    — a content edit (hash break) OR a structural edit after cert.

    Trust root: when ``cert_pem`` is given it is the trust anchor; when None the
    embedded signer cert self-trusts (a self-signed cert vouching for itself), so a
    clean doc reports valid=True without a network round trip. No OCSP/CRL fetching
    (allow_fetching=False) — deterministic on a box behind no egress.

    An unparseable / truncated "signed" file is a DETECTED tamper, not a crash:
    returns {'valid': False, 'tampered': True, ...}.
    """
    result = {
        "valid": False,
        "certified": False,
        "tampered": True,
        "docmdp_ok": False,
        "coverage": "",
        "modification_level": "",
        "signer": "",
        "reason": "",
    }
    try:
        from asn1crypto import x509 as ax509
        from pyhanko.pdf_utils.reader import PdfFileReader
        from pyhanko.sign.fields import MDPPerm
        from pyhanko.sign.validation import (
            read_certification_data,
            validate_pdf_signature,
        )
        from pyhanko_certvalidator import ValidationContext
    except Exception as exc:  # pragma: no cover - import-time only
        result["reason"] = f"validator unavailable: {exc}"
        return result

    try:
        reader = PdfFileReader(io.BytesIO(signed_bytes))
        embedded = reader.embedded_signatures
        if not embedded:
            result["reason"] = "no embedded signature"
            return result
        es = embedded[0]

        # trust root: explicit cert, else self-trust the embedded signer cert
        if cert_pem is not None:
            cert = cx509.load_pem_x509_certificate(_as_bytes(cert_pem))
            trust = [ax509.Certificate.load(cert.public_bytes(_DER))]
        else:
            trust = [es.signer_cert]

        vc = ValidationContext(trust_roots=trust, allow_fetching=False)
        st = validate_pdf_signature(es, signer_validation_context=vc)

        try:
            cd = read_certification_data(reader)
            certified = bool(cd and cd.permission == MDPPerm.NO_CHANGES)
        except Exception:
            certified = False

        intact = bool(st.intact)
        docmdp_ok = bool(st.docmdp_ok)
        # human-readable summary is best-effort — never let it flip the integrity verdict
        try:
            summary = str(st.summary() or "") if callable(getattr(st, "summary", None)) else ""
        except Exception:
            summary = ""
        result.update(
            valid=bool(st.bottom_line),
            certified=certified,
            tampered=(not intact) or (not docmdp_ok),
            docmdp_ok=docmdp_ok,
            coverage=str(getattr(st.coverage, "name", st.coverage) or ""),
            modification_level=str(
                getattr(st.modification_level, "name", st.modification_level) or "NONE"
            ),
            signer=_signer_name(es),
            reason=summary,
        )
        return result
    except Exception as exc:
        # PdfReadError / PdfStreamError / anything: an unparseable signed file is a
        # detected tamper, not an escape.
        result["reason"] = f"{type(exc).__name__}: {exc}"
        result["tampered"] = True
        result["valid"] = False
        return result


def _signer_name(es) -> str:
    try:
        return es.signer_cert.subject.human_friendly
    except Exception:
        return ""


# --- provisioning CLI ---------------------------------------------------------
# `python -m sign.pdf_sign provision --out /path/outside/repo/esign/`
# Generates the cert+key, prints the cert (safe) and the environment variables to
# set, and (with --out) writes the PEMs mode-600. REFUSES to write under the repo root.


def _repo_root():
    from pathlib import Path

    return Path(__file__).resolve().parent.parent


def _provision(out_dir, common_name, org, days):
    import os
    import stat
    from pathlib import Path

    cert_pem, key_pem = generate_self_signed(common_name, org, days)
    if out_dir:
        target = Path(out_dir).resolve()
        repo = _repo_root().resolve()
        # R1.7: never write a private key anywhere under the repo tree.
        if target == repo or repo in target.parents or target.is_relative_to(repo):
            raise SystemExit(
                f"refusing to write signing material under the repo root ({repo}); "
                "choose a path outside the git worktree (e.g. /etc/lifted-sign/esign or "
                "~/.lifted-sign/esign)"
            )
        target.mkdir(parents=True, exist_ok=True)
        cert_path = target / "lifted_signing_cert.pem"
        key_path = target / "lifted_signing_key.pem"
        cert_path.write_bytes(cert_pem)
        key_path.write_bytes(key_pem)
        try:
            os.chmod(key_path, stat.S_IRUSR | stat.S_IWUSR)  # 600 (no-op on Windows ACLs)
            os.chmod(cert_path, stat.S_IRUSR | stat.S_IWUSR | stat.S_IRGRP | stat.S_IROTH)
        except OSError:
            pass
        print(f"wrote {cert_path} (safe to keep)")
        print(f"wrote {key_path} (SECRET — gitignored; never commit)")
        print("\nSet these environment variables (e.g. in your .env, outside the repo):")
        print(f"    SIGN_PADES_CERT_PATH={cert_path}")
        print(f"    SIGN_PADES_KEY_PATH={key_path}")
    else:
        # stdout only — the operator loads these into their secret store out-of-band.
        print(cert_pem.decode("ascii"))
        print(key_pem.decode("ascii"))
        print(
            "# Provide the cert/key to the server via environment (never commit the key):\n"
            "#   SIGN_PADES_CERT_PEM / SIGN_PADES_KEY_PEM  (inline PEM), or\n"
            "#   SIGN_PADES_CERT_PATH / SIGN_PADES_KEY_PATH  (file paths outside the repo)."
        )


def _main(argv=None):
    import argparse

    ap = argparse.ArgumentParser(prog="server.pdf_sign")
    sub = ap.add_subparsers(dest="cmd", required=True)
    pv = sub.add_parser("provision", help="generate a self-signed Lifted signing cert+key")
    pv.add_argument("--out", default=None, help="dir to write PEMs (must be OUTSIDE the repo)")
    pv.add_argument(
        "--cn", default=None, help="cert common name (default: configured legal entity)"
    )
    pv.add_argument(
        "--org", default=None, help="cert organization (default: configured legal entity)"
    )
    pv.add_argument("--days", type=int, default=3650)
    args = ap.parse_args(argv)
    if args.cmd == "provision":
        _provision(args.out, args.cn, args.org, args.days)


if __name__ == "__main__":
    _main()
