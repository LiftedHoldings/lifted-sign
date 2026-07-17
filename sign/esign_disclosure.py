"""Canonical Electronic Records & Signatures Disclosure (ERSD) — single source of truth.

Both the signer page (render) and the Certificate of Completion (embed) MUST use the
EXACT bytes defined here so the SHA-256 hash recorded at consent time matches what the
signer saw and what the certificate proves.

Two forms:
  * ``ERSD_B2B``      — short-form consent-to-do-business-electronically (non-consumer).
  * ``ERSD_CONSUMER`` — full ESIGN 15 U.S.C. §7001(c)(1)(B) consumer disclosure, which
    MUST contain all five elements verbatim: (i) paper-copy right + fee, (ii) right to
    withdraw consent + procedure + consequences, (iii) scope of consent, (iv) procedure
    to update contact info, (v) hardware/software requirements.

``VERSION`` is bumped whenever the text changes (the prior text + hash stay on already
recorded consents, so older agreements remain provable).
"""

from __future__ import annotations

from . import config

VERSION = "ERSD-2026-06-01"
UPDATED_AT = "2026-06-01"

# Operator identity — env-derived (blank by default). The contact address for
# paper-copy/withdraw-consent requests and the legal entity named in the consent
# text come from configuration, never a hardcoded address. COMPANY falls back to
# the product display name so a blank LEGAL_ENTITY still yields readable text.
SUPPORT_EMAIL = config.SUPPORT_EMAIL
COMPANY = config.LEGAL_ENTITY or "Lifted Sign"

HARDWARE_SOFTWARE = (
    "A current web browser (Chrome, Edge, Safari, or Firefox), a PDF reader, "
    "internet access, an email account, and a device able to view and download files."
)

ERSD_B2B = (
    "ELECTRONIC RECORDS & SIGNATURES DISCLOSURE AND CONSENT\n"
    f'{COMPANY} ("Lifted Sign") — Version ' + VERSION + "\n\n"
    'By selecting "I agree to use electronic records and signatures" and proceeding, '
    "you agree that this transaction may be conducted electronically, that your "
    "electronic signature on the document(s) presented to you is the legal equivalent "
    "of your handwritten signature, and that the records relating to this transaction "
    "may be provided to you electronically.\n\n"
    "You may request a paper copy of any signed record at no charge by contacting "
    f"{SUPPORT_EMAIL}. You may withdraw your consent to conduct this transaction "
    f"electronically at any time before signing by contacting {SUPPORT_EMAIL}; the "
    "consequence is that the transaction will not be completed electronically.\n\n"
    "To access and retain the electronic records you will need: " + HARDWARE_SOFTWARE
)

ERSD_CONSUMER = (
    "ELECTRONIC RECORDS & SIGNATURES DISCLOSURE AND CONSENT (CONSUMER)\n"
    f'{COMPANY} ("Lifted Sign") — Version ' + VERSION + "\n\n"
    "Please read this disclosure carefully and keep a copy for your records. Federal "
    "law (the Electronic Signatures in Global and National Commerce Act, 15 U.S.C. "
    "§7001) requires that we obtain your consent to provide certain records to you "
    'electronically and to sign electronically. By selecting "I agree to use '
    'electronic records and signatures" you confirm the following:\n\n'
    "1. PAPER COPIES. You have the right to receive any record provided or made "
    "available electronically in paper form. To request a paper copy, contact us at "
    f"{SUPPORT_EMAIL}. We will provide paper copies at no charge. Requesting a paper "
    "copy will not by itself withdraw your consent to receive records electronically.\n\n"
    "2. WITHDRAWING CONSENT. You have the right to withdraw your consent to receive "
    "records electronically at any time. To withdraw consent, contact us at "
    f"{SUPPORT_EMAIL} or use the withdraw-consent link provided with your signing "
    "invitation. If you withdraw consent before completing this transaction, the "
    "consequence is that the transaction will not be completed electronically and may "
    "be provided to you on paper; there is no fee to withdraw consent. Withdrawal is "
    "effective only after we have a reasonable period of time to process it.\n\n"
    "3. SCOPE OF CONSENT. Your consent applies to this transaction and the specific "
    "record(s) presented to you for signature in this signing session. It does not "
    "extend to other or future transactions unless you separately agree.\n\n"
    "4. UPDATING YOUR CONTACT INFORMATION. To keep your email address and contact "
    "information current with us so that we can deliver electronic records, contact us "
    f"at {SUPPORT_EMAIL} with your updated information.\n\n"
    "5. HARDWARE & SOFTWARE REQUIREMENTS. To access, view, and retain the electronic "
    "records, you will need: " + HARDWARE_SOFTWARE + " If our hardware or software "
    "requirements change in a way that creates a material risk that you will not be "
    "able to access or retain your records, we will notify you and give you the right "
    "to withdraw consent without fee.\n\n"
    'CONSENT. By selecting "I agree" you confirm that: you can access information in '
    "the electronic form that will be used to provide the records (you are able to "
    "view this document on screen); you consent to use electronic records and "
    "electronic signatures for this transaction; and your electronic signature is the "
    "legal equivalent of your handwritten signature."
)


def text_for(consumer: bool) -> str:
    return ERSD_CONSUMER if consumer else ERSD_B2B


def disclosure(consumer: bool) -> dict:
    """The canonical disclosure dict used by signing_payload + the /disclosure endpoint.
    ``text_hash`` is computed here so the page can echo exactly this value back."""
    from . import pdf_edit

    txt = text_for(consumer)
    return {
        "version": VERSION,
        "consumer": bool(consumer),
        "text": txt,
        "text_hash": pdf_edit.sha256(txt.encode("utf-8")),
        "hardware_software": HARDWARE_SOFTWARE,
        "updated_at": UPDATED_AT,
    }
