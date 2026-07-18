#!/usr/bin/env python3
"""
Full end-to-end walkthrough of the Lifted Sign Python SDK.

This script drives an envelope through its entire lifecycle:

    1. Create an agreement (envelope) from a local PDF.
    2. Add a signer.
    3. Place signature/date fields, anchored to text in the PDF.
    4. Send the envelope, which emails the signer a signing link.
    5. Poll until the envelope reaches a terminal state.
    6. Download the sealed, signed PDF and its completion certificate.

Usage:

    export LIFTED_SIGN_KEY=sk_live_xxx
    python examples/full_flow.py contract.pdf dana@example.com "Dana Client"

The signer name is optional and defaults to the signer's email address.
"""

import os
import sys
import pathlib

# The SDK is a bare, zero-dependency single-file module living in sdks/,
# not a pip-installable package, so we point sys.path at that directory
# instead of `pip install`-ing anything.
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent / "sdks"))

from lifted_sign import LiftedSign, LiftedSignError


def main():
    if len(sys.argv) not in (3, 4):
        print(
            f"usage: {sys.argv[0]} <pdf> <signer-email> [signer-name]",
            file=sys.stderr,
        )
        sys.exit(2)

    pdf_path = sys.argv[1]
    signer_email = sys.argv[2]
    signer_name = sys.argv[3] if len(sys.argv) == 4 else signer_email

    if not os.environ.get("LIFTED_SIGN_KEY"):
        # The LiftedSign() constructor would raise on its own, but a
        # friendly message up front is kinder in an example script.
        print(
            "error: LIFTED_SIGN_KEY is not set in the environment.\n"
            "       export LIFTED_SIGN_KEY=sk_live_xxx and try again.",
            file=sys.stderr,
        )
        sys.exit(2)

    try:
        # 1. Client picks up LIFTED_SIGN_KEY from the environment.
        ls = LiftedSign()

        # 2. Create the envelope from the local PDF.
        env = ls.create_agreement(
            pdf_path, name="Full-flow example: " + os.path.basename(pdf_path)
        )
        env_id = env["id"]
        print(f"1. created envelope {env_id}")

        # 3. Add the signer.
        ls.add_signers(env_id, [{"name": signer_name, "email": signer_email}])
        print(f"2. added signer {signer_name} <{signer_email}>")

        # 4. Place fields. Anchor placement snaps a field to literal text
        # already present in the PDF, so the source PDF must contain the
        # strings "Signature:" and "Date:" somewhere on the page. If an
        # anchor can't be resolved, the SDK raises LiftedSignError (the
        # server responds ok:false even with HTTP 200, and the client
        # surfaces that as an exception).
        #
        # For PDFs that don't have anchor text, use normalized coordinates
        # instead, e.g.:
        #   {"signer": signer_email, "type": "signature", "page": 0,
        #    "x": 0.7, "y": 0.9}
        # `page` is zero-based; `x`/`y` are 0..1 fractions of the page
        # unless you pass unit="pt" for absolute points.
        ls.place_fields(
            env_id,
            [
                {"signer": signer_email, "type": "signature", "anchor": "Signature:"},
                {"signer": signer_email, "type": "date", "anchor": "Date:"},
            ],
        )
        print("3. placed signature and date fields")

        # 5. Send the envelope. This emails the signer a single-use link.
        ls.send(env_id)
        print("4. sent envelope; waiting for signer to open the email and sign")

        # 6. Poll until the envelope reaches a terminal state. Note that the
        # envelope's only terminal SUCCESS state is "completed" -- "signed"
        # is a per-signer state, not the envelope's overall state.
        try:
            final = ls.wait_for_completion(env_id, timeout=600, interval=5)
            print(f"5. envelope completed: {final.get('state')}")
        except LiftedSignError as e:
            # Terminal FAILURE state: voided / declined / expired / cancelled.
            state = e.body.get("state") if isinstance(e.body, dict) else None
            print(f"error: envelope failed ({e}); state={state}", file=sys.stderr)
            sys.exit(1)
        except TimeoutError:
            print(
                "envelope still pending after timeout; "
                "it can be polled again later with wait_for_completion()",
                file=sys.stderr,
            )
            sys.exit(1)

        # 7. Download the sealed PDF and the completion certificate.
        signed = ls.download(env_id, "signed.pdf")
        cert = ls.certificate(env_id, "certificate.pdf")
        print(f"6. wrote signed PDF to {signed}")
        print(f"7. wrote certificate to {cert}")

    except LiftedSignError as e:
        print(f"error: {e} (status={e.status}, body={e.body})", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
