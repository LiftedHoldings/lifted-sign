"""PAdES certification primitives (``sign.pdf_sign``) exercised directly.

Self-signed material generation, the cheap ``material_ok`` gate, an end-to-end certify→validate
round-trip on a synthetic PDF, tamper + no-signature detection, and the provisioning CLI's refusal
to write a private key anywhere under the repo tree.
"""

from __future__ import annotations

import io

import pytest


def _one_page_pdf() -> bytes:
    from reportlab.lib.pagesizes import letter
    from reportlab.pdfgen import canvas

    buf = io.BytesIO()
    c = canvas.Canvas(buf, pagesize=letter)
    c.drawString(72, 720, "Certify me")
    c.showPage()
    c.save()
    return buf.getvalue()


def test_generate_self_signed_pair_parses():
    from sign import pdf_sign

    cert_pem, key_pem = pdf_sign.generate_self_signed("Test CN", "Test Org", days=30)
    assert cert_pem.startswith(b"-----BEGIN CERTIFICATE-----")
    assert b"PRIVATE KEY" in key_pem
    assert pdf_sign.material_ok(cert_pem, key_pem) is True


def test_material_ok_rejects_bad_material():
    from sign import pdf_sign

    assert pdf_sign.material_ok(None, None) is False
    assert pdf_sign.material_ok(b"garbage", b"garbage") is False
    # mismatched pair (two independent keys) is rejected
    cert1, _k1 = pdf_sign.generate_self_signed("A", "A", 30)
    _c2, key2 = pdf_sign.generate_self_signed("B", "B", 30)
    assert pdf_sign.material_ok(cert1, key2) is False


def test_certify_then_validate_round_trip():
    from sign import pdf_sign

    cert_pem, key_pem = pdf_sign.generate_self_signed("Signer", "Org", 365)
    signed = pdf_sign.certify_pdf(_one_page_pdf(), cert_pem, key_pem)
    v = pdf_sign.validate(signed)
    assert v["valid"] is True
    assert v["certified"] is True
    assert v["tampered"] is False
    assert v["docmdp_ok"] is True
    # explicit trust root (the same cert) also validates
    v2 = pdf_sign.validate(signed, cert_pem=cert_pem)
    assert v2["valid"] is True


def test_validate_reports_no_signature_on_plain_pdf():
    from sign import pdf_sign

    v = pdf_sign.validate(_one_page_pdf())
    assert v["valid"] is False
    assert v["reason"] == "no embedded signature"


def test_validate_flags_tampered_bytes():
    from sign import pdf_sign

    cert_pem, key_pem = pdf_sign.generate_self_signed("Signer", "Org", 365)
    signed = bytearray(pdf_sign.certify_pdf(_one_page_pdf(), cert_pem, key_pem))
    signed[len(signed) // 2] ^= 0xAA
    v = pdf_sign.validate(bytes(signed))
    assert v["tampered"] is True
    assert v["valid"] is False


def test_provision_refuses_to_write_under_repo_root(tmp_path):
    from sign import pdf_sign

    repo = pdf_sign._repo_root()
    inside = repo / "esign_keys_should_not_land_here"
    with pytest.raises(SystemExit):
        pdf_sign._provision(str(inside), None, None, 3650)
    assert not inside.exists()


def test_provision_writes_outside_repo(tmp_path, capsys):
    from sign import pdf_sign

    out = tmp_path / "keys"
    pdf_sign._provision(str(out), "CN", "Org", 30)
    assert (out / "lifted_signing_cert.pem").exists()
    assert (out / "lifted_signing_key.pem").exists()
    printed = capsys.readouterr().out
    assert "SIGN_PADES_CERT_PATH=" in printed
