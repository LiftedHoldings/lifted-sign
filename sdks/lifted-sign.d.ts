// Type definitions for the Lifted Sign Node SDK (sdks/lifted-sign.mjs)
// Hand-authored to mirror the JSDoc @typedefs and public API of the client.
// SPDX-License-Identifier: MIT

/**
 * A person who must sign an envelope.
 */
export interface Signer {
  /** Signer's full name, shown on the signing page and certificate. */
  name: string;
  /** Signer's email; also the stable key used to target fields. */
  email: string;
}

/** Field kinds that can be stamped onto the PDF. */
export type FieldType =
  | "signature"
  | "initials"
  | "date"
  | "text"
  | "name"
  | "email"
  | "checkbox";

/** Where a field sits relative to its anchor text. */
export type FieldPlacement = "right" | "left" | "below" | "above" | "over";

/**
 * One field to stamp onto the PDF for a given signer. Supply exactly one
 * location strategy: `anchor` (recommended), absolute points (`x`/`y` with
 * `unit: "pt"`), or normalized 0..1 coordinates (`x`/`y` without `unit`).
 */
export interface Field {
  /** Email of the signer this field belongs to (must match a {@link Signer}). */
  signer: string;
  /** Field kind. */
  type: FieldType;
  /** Literal text already in the PDF to snap the field beside. */
  anchor?: string;
  /** Which occurrence of `anchor` to use when it repeats (0-based). */
  anchor_index?: number;
  /** Where to sit relative to the anchor. */
  place?: FieldPlacement;
  /** Horizontal nudge from the anchor, in PDF points. */
  dx?: number;
  /** Vertical nudge from the anchor, in PDF points. */
  dy?: number;
  /** Zero-based page index for points/normalized placement. */
  page?: number;
  /** X coordinate (PDF points when `unit: "pt"`, else 0..1 fraction of page width). */
  x?: number;
  /** Y coordinate (PDF points when `unit: "pt"`, else 0..1 fraction of page height). */
  y?: number;
  /** Set to `"pt"` for absolute points; omit for normalized 0..1 coords. */
  unit?: "pt";
}

/** Options accepted by the {@link LiftedSign} constructor. */
export interface LiftedSignOptions {
  /** Secret API key (e.g. `sk_live_...`). Defaults to the `LIFTED_SIGN_KEY` env var. */
  apiKey?: string;
  /** API host; trailing slashes are stripped. Default `https://sign.liftedholdings.com`. */
  baseUrl?: string;
  /** Per-request timeout in milliseconds. Default 30000. */
  timeout?: number;
}

/**
 * An agreement (envelope) record as returned by the API. Typed loosely: the
 * server may add fields over time, so only the id is declared required.
 */
export interface Agreement {
  id: string | number;
  [key: string]: unknown;
}

/** One page of results from the list endpoint. */
export interface AgreementPage {
  agreements: Agreement[];
  has_more?: boolean;
  [key: string]: unknown;
}

/**
 * The single error type this module throws. Every failure - network abort,
 * non-2xx HTTP status, or an application-level `{ ok: false }` response - is
 * normalized into a `LiftedSignError`.
 */
export class LiftedSignError extends Error {
  constructor(
    message: string,
    details?: { status?: number | null; body?: unknown }
  );
  /**
   * HTTP status code when the failure came from a response (or `200` for an
   * app-level `{ ok: false }` error); `null` for pre-response failures such as
   * a timeout/abort.
   */
  status: number | null;
  /** Parsed response body when available (object, string, or `null`). */
  body: unknown;
}

/**
 * Client for the Lifted Sign e-signature API. Construct one instance per API
 * key, then call the lifecycle methods against envelope ids it returns. All
 * methods are async and reject with a {@link LiftedSignError} on any failure.
 */
export class LiftedSign {
  /**
   * @throws {LiftedSignError} If no API key is supplied and none is in the
   * environment (`LIFTED_SIGN_KEY`).
   */
  constructor(options?: LiftedSignOptions);

  apiKey: string;
  baseUrl: string;
  timeout: number;

  /** Create a draft envelope by uploading a local PDF (step 1 of the lifecycle). */
  createAgreement(pdfPath: string, options?: { name?: string }): Promise<Agreement>;

  /** Fetch one page of agreements. The server clamps `limit` to 1..200. */
  listAgreements(options?: { limit?: number; offset?: number }): Promise<AgreementPage>;

  /**
   * Iterate over ALL agreements, transparently fetching pages as needed.
   * Usage: `for await (const agreement of client.iterateAgreements()) { ... }`
   */
  iterateAgreements(options?: { pageSize?: number }): AsyncGenerator<Agreement, void, void>;

  /** Fetch a single envelope by id - use it to poll status. */
  get(aid: string | number): Promise<Agreement>;

  /**
   * Poll {@link LiftedSign.get} until the envelope reaches a terminal state,
   * then resolve with the final agreement. The only terminal SUCCESS state is
   * `"completed"` (`"signed"` is signer-level). Throws {@link LiftedSignError}
   * if the envelope ends as voided / declined / expired / cancelled, or if
   * `timeout` ms elapse first.
   */
  waitForCompletion(
    aid: string | number,
    options?: { timeout?: number; interval?: number }
  ): Promise<Agreement>;

  /** Permanently delete a draft envelope. */
  delete(aid: string | number): Promise<unknown>;

  /** Attach the people who must sign (step 2). Resolves with the saved signer list. */
  addSigners(aid: string | number, signers: Signer[]): Promise<unknown>;

  /** Position signature/date/text fields per signer (step 3). */
  placeFields(aid: string | number, fields: Field[]): Promise<unknown>;

  /** Freeze the PDF and email each signer a single-use link (step 4). */
  send(aid: string | number): Promise<unknown>;

  /** Re-send the signing email to signers who have not finished yet. */
  remind(aid: string | number): Promise<unknown>;

  /** Void a sent envelope so it can no longer be signed. `reason` is recorded
   * on the audit trail and shown to signers. */
  void(aid: string | number, reason?: string): Promise<unknown>;

  /** Download the sealed, signed PDF to `outPath`; resolves with the written path. */
  download(aid: string | number, outPath: string): Promise<string>;

  /** Download the certificate of completion PDF to `outPath`; resolves with the written path. */
  certificate(aid: string | number, outPath: string): Promise<string>;

  /** Fetch the account record for the API key in use. */
  account(): Promise<unknown>;
}
