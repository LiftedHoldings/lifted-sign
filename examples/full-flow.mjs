/**
 * Lifted Sign SDK — full flow example (Node)
 * ============================================
 *
 * Demonstrates the complete lifecycle against a live envelope:
 *   create -> add signer -> place fields -> send -> poll to completion
 *   -> download sealed PDF + certificate.
 *
 * This is the Node twin of examples/full_flow.py, using the zero-dependency
 * ESM client at sdks/lifted-sign.mjs.
 *
 * Requires Node 18+ (for global fetch) and has zero npm dependencies.
 *
 * Usage:
 *   export LIFTED_SIGN_KEY=sk_live_xxx
 *   node examples/full-flow.mjs contract.pdf dana@example.com "Dana Client"
 */

// This is a relative import, so it resolves against this file's location
// (not the process cwd) — the script works from any working directory.
import { LiftedSign, LiftedSignError } from "../sdks/lifted-sign.mjs";
import { basename } from "node:path";

const [pdfPath, signerEmail, signerName = signerEmail] = process.argv.slice(2);

if (!pdfPath || !signerEmail) {
  console.error(
    'usage: node examples/full-flow.mjs <pdf-path> <signer-email> ["Signer Name"]'
  );
  process.exit(2);
}

if (!process.env.LIFTED_SIGN_KEY) {
  console.error(
    "LIFTED_SIGN_KEY is not set. export LIFTED_SIGN_KEY=sk_live_xxx and try again."
  );
  process.exit(2);
}

async function main() {
  // 1. Client reads LIFTED_SIGN_KEY from the environment.
  const ls = new LiftedSign();

  // 2. Create the envelope from a local PDF.
  const env = await ls.createAgreement(pdfPath, {
    name: `Full-flow example: ${basename(pdfPath)}`,
  });
  console.log(`[1/6] created envelope ${env.id}`);

  // 3. Add the signer.
  await ls.addSigners(env.id, [{ name: signerName, email: signerEmail }]);
  console.log(`[2/6] added signer ${signerName} <${signerEmail}>`);

  // 4. Place fields via anchor text: each field snaps to literal text already
  // present in the PDF, so the source document must contain "Signature:" and
  // "Date:" somewhere on the page. If an anchor string can't be found, this
  // call rejects with a LiftedSignError — the server reports ok:false even
  // on HTTP 200, and the client surfaces that as a thrown error.
  //
  // For PDFs without anchor text, use absolute coordinates instead, e.g.:
  //   { signer: signerEmail, type: "signature", page: 0, x: 0.7, y: 0.9 }
  // `page` is zero-based; x/y are normalized 0..1 unless you pass unit: "pt".
  await ls.placeFields(env.id, [
    { signer: signerEmail, type: "signature", anchor: "Signature:" },
    { signer: signerEmail, type: "date", anchor: "Date:" },
  ]);
  console.log("[3/6] placed signature and date fields");

  // 5. Send for signature — each signer gets a single-use link by email.
  await ls.send(env.id);
  console.log("[4/6] sent envelope; waiting on signer to complete it");

  // 6. Poll until the envelope reaches a terminal state.
  //
  // IMPORTANT: unlike the Python SDK, which raises a distinct TimeoutError
  // on poll timeout, this Node client throws LiftedSignError for BOTH a
  // terminal failure state (voided / declined / expired / cancelled) AND a
  // poll timeout — there is no separate timeout error class here. This
  // asymmetry with Python is intentional in the SDK design.
  //
  // Also note: "completed" is the only terminal SUCCESS state for the
  // envelope as a whole. "signed" is a signer-level status, not an envelope
  // status.
  let final;
  try {
    final = await ls.waitForCompletion(env.id, {
      timeout: 600_000,
      interval: 5_000,
    });
  } catch (err) {
    if (err instanceof LiftedSignError) {
      const status = err.body?.status ? ` (status: ${err.body.status})` : "";
      console.error(`[5/6] failed waiting for completion: ${err.message}${status}`);
      process.exit(1);
    }
    throw err;
  }
  console.log(`[5/6] envelope reached terminal status: ${final.status}`);

  // 7. Download the sealed PDF and the certificate of completion.
  const pdfOut = await ls.download(env.id, "signed.pdf");
  const certOut = await ls.certificate(env.id, "certificate.pdf");
  console.log(`[6/6] wrote ${pdfOut} and ${certOut}`);
}

main().catch((err) => {
  if (err instanceof LiftedSignError) {
    console.error(`API error: ${err.message}`, err.status ?? "", err.body ?? "");
  } else {
    console.error(err);
  }
  process.exit(1);
});
