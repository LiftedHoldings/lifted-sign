// Lifted Sign Node SDK
// Copyright (c) 2026 Daniel Wilson Kemp
// SPDX-License-Identifier: MIT
//
// This client SDK is MIT-licensed and may be freely vendored into any project,
// open or closed — it is deliberately kept under a permissive license so that
// integrating against Lifted Sign never subjects your application to the AGPL
// that covers the Lifted Sign server. See sdks/LICENSE for the full MIT text.

/**
 * Lifted Sign API — zero-dependency Node client.
 *
 * A single-file SDK for the Lifted Sign e-signature service. There is nothing to
 * `npm install`: it relies only on the built-in global `fetch`, `FormData`, and
 * `Blob` (available in Node 18+) plus two `node:` core modules for local file I/O.
 * Drop this file into your project and go.
 *
 * ## Quick start
 * ```js
 *   import { LiftedSign } from "./lifted-sign.mjs";
 *
 *   const ls = new LiftedSign({ apiKey: "sk_live_..." });   // or LIFTED_SIGN_KEY in the env
 *   const env = await ls.createAgreement("contract.pdf", { name: "Master Services Agreement" });
 *   await ls.addSigners(env.id, [{ name: "Dana Client", email: "dana@example.com" }]);
 *   await ls.placeFields(env.id, [
 *     { signer: "dana@example.com", type: "signature", anchor: "Signature:" },
 *     { signer: "dana@example.com", type: "date",      anchor: "Date:" },
 *   ]);
 *   await ls.send(env.id);                                  // emails each signer a single-use link
 * ```
 *
 * ## The signing lifecycle
 * Every document (an "envelope" / "agreement") moves through a fixed sequence:
 *   1. {@link LiftedSign#createAgreement} — upload the PDF, get back a draft envelope.
 *   2. {@link LiftedSign#addSigners}      — attach the people who must sign.
 *   3. {@link LiftedSign#placeFields}     — position signature/date/text fields per signer.
 *   4. {@link LiftedSign#send}            — freeze the PDF and email each signer a link.
 * After sending you can {@link LiftedSign#remind} or {@link LiftedSign#void} the
 * envelope, poll it with {@link LiftedSign#get}, and once every signer is done,
 * {@link LiftedSign#download} the sealed PDF and its {@link LiftedSign#certificate}
 * of completion.
 *
 * ## Field placement
 * Field placement is by ANCHOR — you name text that already exists in the PDF
 * ("Signature:") and the field snaps to it. No coordinate math. (Absolute PDF points
 * and normalized 0..1 coordinates are supported too; see {@link LiftedSign#placeFields}.)
 *
 * ## Run it from a shell
 * The file is also an executable script — send your first document in one command:
 * ```sh
 *   export LIFTED_SIGN_KEY=sk_live_xxx
 *   node lifted-sign.mjs contract.pdf dana@example.com "Dana Client"
 * ```
 *
 * @see LiftedSign          — the client class; one instance per API key.
 * @see LiftedSignError     — the only error type thrown by this module.
 * @license MIT
 * @module lifted-sign
 *
 * @typedef {Object} Signer
 * @property {string} name  Signer's full name, shown on the signing page and certificate.
 * @property {string} email Signer's email; also the stable key used to target fields.
 *
 * @typedef {Object} Field
 *   One field to stamp onto the PDF for a given signer. Supply exactly one location
 *   strategy — `anchor` (recommended), absolute `points`, or `normalized` coords.
 * @property {string} signer Email of the signer this field belongs to (must match a {@link Signer}).
 * @property {("signature"|"initials"|"date"|"text"|"name"|"email"|"checkbox")} type Field kind.
 * @property {string} [anchor] Literal text already in the PDF to snap the field beside.
 * @property {number} [anchor_index] Which occurrence of `anchor` to use when it repeats (0-based).
 * @property {("right"|"left"|"below"|"above"|"over")} [place] Where to sit relative to the anchor.
 * @property {number} [dx] Horizontal nudge from the anchor, in PDF points.
 * @property {number} [dy] Vertical nudge from the anchor, in PDF points.
 * @property {number} [page] Zero-based page index for `points`/`normalized` placement.
 * @property {number} [x] X coordinate (PDF points when `unit:"pt"`, else 0..1 fraction of page width).
 * @property {number} [y] Y coordinate (PDF points when `unit:"pt"`, else 0..1 fraction of page height).
 * @property {("pt")} [unit] Set to `"pt"` for absolute points; omit for normalized 0..1 coords.
 */

import { readFile, writeFile } from "node:fs/promises";
import { basename } from "node:path";

/**
 * Default API host. Every request path is appended to this base URL unless the
 * caller overrides it via the constructor's `baseUrl` option.
 * @type {string}
 */
const DEFAULT_BASE_URL = "https://sign.liftedholdings.com";

/**
 * The single error type this module throws. Every failure — network abort, non-2xx
 * HTTP status, or an application-level `{ ok:false }` response — is normalized into a
 * `LiftedSignError` so callers only ever need one `catch` shape.
 *
 * @extends Error
 * @property {?number} status HTTP status code when the failure came from a response
 *   (or `200` for an app-level `{ ok:false }` error); `null` for pre-response failures
 *   such as a timeout/abort.
 * @property {*} body Parsed response body when available (object, string, or `null`) —
 *   useful for reading the server's `error` message or field-level diagnostics.
 */
export class LiftedSignError extends Error {
  /**
   * @param {string} message Human-readable description of what went wrong.
   * @param {Object} [details]
   * @param {?number} [details.status=null] HTTP status associated with the failure, if any.
   * @param {*} [details.body=null] Parsed response body associated with the failure, if any.
   */
  constructor(message, { status = null, body = null } = {}) {
    super(message);
    this.name = "LiftedSignError";
    this.status = status;
    this.body = body;
  }
}

/**
 * Client for the Lifted Sign e-signature API. Construct one instance per API key,
 * then call the lifecycle methods against envelope ids it returns. All methods are
 * async and reject with a {@link LiftedSignError} on any failure.
 *
 * @example
 * const ls = new LiftedSign();                 // reads LIFTED_SIGN_KEY from the env
 * const env = await ls.createAgreement("nda.pdf");
 * await ls.addSigners(env.id, [{ name: "A. Signer", email: "a@example.com" }]);
 * await ls.placeFields(env.id, [{ signer: "a@example.com", type: "signature", anchor: "Sign here" }]);
 * await ls.send(env.id);
 */
export class LiftedSign {
  /**
   * @param {Object} [options]
   * @param {string} [options.apiKey=process.env.LIFTED_SIGN_KEY] Secret API key
   *   (e.g. `sk_live_...`). Defaults to the `LIFTED_SIGN_KEY` environment variable.
   * @param {string} [options.baseUrl="https://sign.liftedholdings.com"] API host;
   *   any trailing slashes are stripped so path concatenation stays clean.
   * @param {number} [options.timeout=30000] Per-request timeout in milliseconds;
   *   a request exceeding this is aborted and rejects with a {@link LiftedSignError}.
   * @throws {LiftedSignError} If no API key is supplied and none is in the environment.
   */
  constructor({ apiKey = process.env.LIFTED_SIGN_KEY, baseUrl = DEFAULT_BASE_URL, timeout = 30000 } = {}) {
    if (!apiKey) throw new LiftedSignError("No API key. Pass { apiKey } or set LIFTED_SIGN_KEY.");
    this.apiKey = apiKey;
    // Normalize away trailing slashes so `this.baseUrl + path` never doubles up "//".
    this.baseUrl = baseUrl.replace(/\/+$/, "");
    this.timeout = timeout;
  }

  // -- low-level request ---------------------------------------------------
  /**
   * Core HTTP helper shared by every public method. Handles bearer auth, the abort
   * timeout, response parsing, and the module's uniform error normalization. Most
   * callers should use a higher-level method instead of calling this directly.
   *
   * @private
   * @param {string} method HTTP verb, e.g. `"GET"`, `"POST"`, `"DELETE"`.
   * @param {string} path Request path appended to `baseUrl`, e.g. `"/api/mysign/account"`.
   * @param {Object} [options]
   * @param {(string|FormData|undefined)} [options.body] Request body. A JSON string
   *   (paired with a `Content-Type` header) or a `FormData` for multipart uploads.
   * @param {Object<string,string>} [options.headers={}] Extra headers merged over the
   *   defaults (`Authorization`, `Accept`); later keys win.
   * @param {boolean} [options.raw=false] When `true`, resolve to a `Buffer` of the raw
   *   response bytes (for PDF downloads) instead of parsed JSON.
   * @returns {Promise<(Object|string|Buffer)>} Parsed JSON (object/string), or a
   *   `Buffer` when `raw` is set.
   * @throws {LiftedSignError} On a non-2xx status, an app-level `{ ok:false }` body,
   *   or an aborted/failed request.
   */
  async _request(method, path, { body = undefined, headers = {}, raw = false } = {}) {
    // Enforce the timeout with an AbortController: fire abort() after `this.timeout` ms.
    const ctrl = new AbortController();
    const t = setTimeout(() => ctrl.abort(), this.timeout);
    let resp;
    try {
      resp = await fetch(this.baseUrl + path, {
        method,
        body,
        signal: ctrl.signal,
        // Bearer auth on every call; caller headers (e.g. Content-Type) override the defaults.
        headers: { Authorization: "Bearer " + this.apiKey, Accept: "application/json", ...headers },
      });
    } finally {
      // Always clear the timer so a fast response doesn't leave a dangling abort pending.
      clearTimeout(t);
    }
    if (raw) {
      // Binary path (PDF downloads): no JSON parsing — status check, then hand back bytes.
      if (!resp.ok) throw new LiftedSignError(`${method} ${path} -> HTTP ${resp.status}`, { status: resp.status });
      return Buffer.from(await resp.arrayBuffer());
    }
    const text = await resp.text();
    let data = {};
    try {
      // Empty body → {}. Otherwise parse JSON, but tolerate a non-JSON body (fall through).
      data = text ? JSON.parse(text) : {};
    } catch {
      data = text;
    }
    if (!resp.ok) {
      throw new LiftedSignError(`${method} ${path} -> HTTP ${resp.status}`, { status: resp.status, body: data });
    }
    // Placement/mutation endpoints return { ok:false, error } with HTTP 200 when a field can't be
    // resolved — surface it, never a silent drop on a legal document.
    if (data && typeof data === "object" && data.ok === false) {
      throw new LiftedSignError(`${method} ${path} -> ${data.error || "error"}`, { status: 200, body: data });
    }
    return data;
  }

  /**
   * Convenience wrapper around {@link LiftedSign#_request} for JSON request bodies:
   * serializes `payload` and sets the `Content-Type: application/json` header.
   *
   * @private
   * @param {string} method HTTP verb.
   * @param {string} path Request path appended to `baseUrl`.
   * @param {Object} payload Value to `JSON.stringify` as the request body.
   * @returns {Promise<(Object|string)>} The parsed response, per {@link LiftedSign#_request}.
   */
  _json(method, path, payload) {
    return this._request(method, path, {
      body: JSON.stringify(payload),
      headers: { "Content-Type": "application/json" },
    });
  }

  // -- envelopes -----------------------------------------------------------
  /**
   * Create a draft envelope by uploading a PDF (multipart). This is step 1 of the
   * signing lifecycle; the returned envelope's `id` is passed to every later call.
   * The file is read from disk and sent as `application/pdf`.
   *
   * @param {string} pdfPath Filesystem path to the source PDF.
   * @param {Object} [options]
   * @param {string} [options.name] Human-friendly envelope name; defaults to the
   *   PDF's base filename when omitted.
   * @returns {Promise<Object>} The created envelope, including its `id`.
   * @throws {LiftedSignError} If the upload is rejected by the API.
   */
  async createAgreement(pdfPath, { name } = {}) {
    const bytes = await readFile(pdfPath);
    const form = new FormData();
    form.append("name", name || basename(pdfPath));
    form.append("file", new Blob([bytes], { type: "application/pdf" }), basename(pdfPath));
    return this._request("POST", "/api/mysign/agreements", { body: form });
  }

  /**
   * List envelopes belonging to this account, newest first, with paging.
   *
   * @param {Object} [options]
   * @param {number} [options.limit=50] Maximum number of envelopes to return.
   * @param {number} [options.offset=0] Number of envelopes to skip (for paging).
   * @returns {Promise<Object>} A page of envelopes.
   */
  listAgreements({ limit = 50, offset = 0 } = {}) {
    return this._request("GET", `/api/mysign/agreements?limit=${limit}&offset=${offset}`);
  }

  /**
   * Fetch a single envelope by id — use it to poll status (e.g. who has signed).
   *
   * @param {(string|number)} aid Envelope id.
   * @returns {Promise<Object>} The envelope's current state.
   */
  get(aid) {
    return this._request("GET", `/api/mysign/agreements/${aid}`);
  }

  /**
   * Permanently delete a draft envelope.
   *
   * @param {(string|number)} aid Envelope id.
   * @returns {Promise<Object>} The delete confirmation.
   */
  delete(aid) {
    return this._request("DELETE", `/api/mysign/agreements/${aid}`);
  }

  // -- signers / fields ----------------------------------------------------
  /**
   * Set (replace) the envelope's signer list. This is step 2 of the lifecycle and
   * must precede {@link LiftedSign#placeFields}, since fields target signers by email.
   *
   * @param {(string|number)} aid Envelope id.
   * @param {Signer[]} signers The signers, e.g. `[{ name, email }, ...]`.
   * @returns {Promise<Object>} The saved signer list.
   */
  addSigners(aid, signers) {
    return this._json("POST", `/api/mysign/agreements/${aid}/signers`, { signers });
  }

  /**
   * Place signature/date/text fields onto the PDF. Step 3 of the lifecycle. Each field
   * targets a signer by `signer` (their email) and a location by exactly one of three
   * strategies:
   *
   *   anchor     : { signer, type: "signature", anchor: "Signature:" }   (recommended)
   *                optional: anchor_index (nth match), place (right|left|below|above|over),
   *                dx/dy (nudge, PDF points)
   *   points     : { signer, type: "signature", page: 0, x: 100, y: 200, unit: "pt" }
   *   normalized : { signer, type: "signature", page: 0, x: 0.5, y: 0.5 }   (0..1)
   *
   * Field `type` is one of: signature, initials, date, text, name, email, checkbox.
   *
   * Fail-closed: if any field can't be resolved the whole batch is rejected (the API
   * returns `{ ok:false }`, which this SDK raises as a {@link LiftedSignError}) — a legal
   * document never gets a silently dropped field.
   *
   * @param {(string|number)} aid Envelope id.
   * @param {Field[]} fields The fields to place; see the placement strategies above.
   * @returns {Promise<Object>} Placement result (includes a `count` of fields placed).
   * @throws {LiftedSignError} If any field can't be resolved (the batch is all-or-nothing).
   */
  placeFields(aid, fields) {
    return this._json("POST", `/api/mysign/agreements/${aid}/fields`, { fields });
  }

  // -- sending -------------------------------------------------------------
  /**
   * Freeze the PDF and email each signer a single-use signing link. Step 4 — this is
   * the point of no return: the document can no longer be edited, only signed, reminded,
   * or voided.
   *
   * @param {(string|number)} aid Envelope id.
   * @returns {Promise<Object>} The send confirmation.
   */
  send(aid) {
    return this._json("POST", `/api/mysign/agreements/${aid}/send`, {});
  }

  /**
   * Re-email the signing link to any signer who has not yet completed the envelope.
   *
   * @param {(string|number)} aid Envelope id.
   * @returns {Promise<Object>} The reminder confirmation.
   */
  remind(aid) {
    return this._json("POST", `/api/mysign/agreements/${aid}/remind`, {});
  }

  /**
   * Void a sent envelope, invalidating every outstanding signing link.
   *
   * @param {(string|number)} aid Envelope id.
   * @param {string} [reason=""] Optional reason recorded on the audit trail and shown to signers.
   * @returns {Promise<Object>} The void confirmation.
   */
  void(aid, reason = "") {
    return this._json("POST", `/api/mysign/agreements/${aid}/void`, { reason });
  }

  // -- downloads -----------------------------------------------------------
  /**
   * Download the sealed, fully-signed PDF and write it to disk. Available once the
   * envelope is complete.
   *
   * @param {(string|number)} aid Envelope id.
   * @param {string} outPath Destination path for the PDF.
   * @returns {Promise<string>} The `outPath` it was written to.
   * @throws {LiftedSignError} If the document isn't downloadable (e.g. not yet complete).
   */
  async download(aid, outPath) {
    await writeFile(outPath, await this._request("GET", `/api/mysign/agreements/${aid}/download`, { raw: true }));
    return outPath;
  }

  /**
   * Download the Certificate of Completion PDF (audit trail: signer identities, IP
   * addresses, timestamps) and write it to disk.
   *
   * @param {(string|number)} aid Envelope id.
   * @param {string} outPath Destination path for the certificate PDF.
   * @returns {Promise<string>} The `outPath` it was written to.
   * @throws {LiftedSignError} If the certificate isn't available yet.
   */
  async certificate(aid, outPath) {
    await writeFile(outPath, await this._request("GET", `/api/mysign/agreements/${aid}/certificate`, { raw: true }));
    return outPath;
  }

  /**
   * Fetch account details for the current API key (plan, usage, identity).
   *
   * @returns {Promise<Object>} The account record.
   */
  account() {
    return this._request("GET", "/api/mysign/account");
  }
}

// -- CLI: `node lifted-sign.mjs <pdf> <signer-email> [signer-name] [anchor]` ----------------------
// When this file is executed directly (rather than imported), run the full four-step
// lifecycle end-to-end for a single signer and print progress. `isMain` is true when the
// module URL matches the invoked script path — the `.endsWith` clause covers argv paths
// that aren't a `file://` URL match (e.g. symlinks or a bare relative invocation).
const isMain = import.meta.url === `file://${process.argv[1]}` || process.argv[1]?.endsWith("lifted-sign.mjs");
if (isMain) {
  // Positional args: <pdf> <signer-email> [signer-name] [anchor]; anchor defaults to "Signature:".
  const [pdf, email, name, anchor = "Signature:"] = process.argv.slice(2);
  if (!pdf || !email) {
    console.log("usage: node lifted-sign.mjs <pdf> <signer-email> [signer-name] [anchor]");
    process.exit(2); // exit 2 = usage error (missing required args)
  }
  const ls = new LiftedSign(); // API key comes from LIFTED_SIGN_KEY in the environment
  try {
    // Walk the lifecycle: create -> add signer -> place field -> send, narrating each step.
    const env = await ls.createAgreement(pdf, { name: basename(pdf) });
    console.log(`1/4  created envelope #${env.id}`);
    await ls.addSigners(env.id, [{ name: name || email, email }]);
    console.log(`2/4  added signer ${email}`);
    const res = await ls.placeFields(env.id, [{ signer: email, type: "signature", anchor }]);
    console.log(`3/4  placed ${res.count ?? 0} field(s) at anchor ${JSON.stringify(anchor)}`);
    await ls.send(env.id);
    console.log(`4/4  sent — ${email} has a signing link in their inbox`);
    console.log(`\nTrack it:  ${ls.baseUrl} · envelope #${env.id}`);
  } catch (e) {
    // Any LiftedSignError (or other throw) lands here: print the message, then the parsed
    // server body if one was attached, and exit non-zero for shell/callers.
    console.error(`error: ${e.message}`);
    if (e.body) console.error(JSON.stringify(e.body, null, 2));
    process.exit(1);
  }
}
