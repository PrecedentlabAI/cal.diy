import { createHmac, timingSafeEqual } from "node:crypto";

/**
 * HMAC-SHA256-signed state for the PL OAuth wrapper routes.
 *
 * The previous design encoded {userId, redirectUri} as plain JSON in the
 * state= query param. Any attacker could rewrite userId to attach a
 * Calendar credential to a different cal.diy user (classic confused-
 * deputy). Codex review flagged this on 2026-05-19. This module fixes
 * it by signing the state payload and verifying the signature on the
 * /save callback.
 *
 * Wire format:
 *   state = base64url(JSON.stringify(payload)) + "." + base64url(hmacSha256(payloadB64))
 *
 * Two secrets supported simultaneously (primary + previous) so a
 * CALCOM_OAUTH_STATE_HMAC_KEY rotation doesn't invalidate in-flight OAuth
 * flows. New states sign with primary. Verifier tries primary first,
 * falls back to previous. Operators rotate by:
 *   1. set _PREVIOUS = current primary
 *   2. set primary = new key
 *   3. after 30 min (state TTL), unset _PREVIOUS
 */

// 60 minutes: long enough to absorb Google MFA + account-switcher
// detours on the success path (codex pass-9 P2), still tight enough
// to bound replay of a stolen state. Cancel path bypasses the TTL
// entirely via verifyState({ skipTtl: true }).
export const STATE_TTL_SECONDS = 60 * 60;

export interface SignedStatePayload {
  userId: number;
  redirectUri: string;
  iat: number; // issued-at, unix seconds
}

export class StateSignatureError extends Error {
  constructor(reason: string) {
    super(`invalid signed state: ${reason}`);
    this.name = "StateSignatureError";
  }
}

function base64urlEncode(buf: Buffer): string {
  return buf.toString("base64").replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

function base64urlDecode(s: string): Buffer {
  const pad = s.length % 4 === 0 ? "" : "=".repeat(4 - (s.length % 4));
  return Buffer.from(s.replace(/-/g, "+").replace(/_/g, "/") + pad, "base64");
}

function hmac(payloadB64: string, secret: string): Buffer {
  return createHmac("sha256", secret).update(payloadB64).digest();
}

/**
 * Sign a state payload. Caller supplies all fields except iat — we stamp
 * issued-at here so the TTL window is honest.
 */
export function signState(
  payload: Omit<SignedStatePayload, "iat">,
  secret: string,
  now: () => number = Date.now,
): string {
  if (!secret) throw new Error("signState: secret is empty — refusing to sign");

  const body: SignedStatePayload = {
    ...payload,
    iat: Math.floor(now() / 1000),
  };
  const payloadB64 = base64urlEncode(Buffer.from(JSON.stringify(body), "utf8"));
  const sig = base64urlEncode(hmac(payloadB64, secret));
  return `${payloadB64}.${sig}`;
}

/**
 * Verify and parse a signed state token. Tries each secret in order.
 * Throws StateSignatureError on any failure (malformed, bad signature,
 * expired). Returns the parsed payload on success.
 *
 * The caller is responsible for validating semantic fields (e.g. that
 * userId points at a real cal.diy user, that redirectUri is on an
 * allowlist if you have one) — this module only proves origin + freshness.
 */
export interface VerifyStateOptions {
  /**
   * Skip the TTL check. Used by the OAuth cancel branch so users who sit
   * on the Google consent screen for longer than STATE_TTL_SECONDS still
   * get a friendly redirect back, instead of a 400 from the callback.
   * Signature is still verified — only freshness is relaxed.
   */
  skipTtl?: boolean;
}

export function verifyState(
  token: string,
  secrets: ReadonlyArray<string>,
  now: () => number = Date.now,
  options: VerifyStateOptions = {},
): SignedStatePayload {
  if (typeof token !== "string" || !token.includes(".")) {
    throw new StateSignatureError("missing or malformed token");
  }
  const usable = secrets.filter((s): s is string => typeof s === "string" && s.length > 0);
  if (usable.length === 0) {
    throw new StateSignatureError("no signing secrets configured");
  }

  const [payloadB64, sigB64, ...rest] = token.split(".");
  if (!payloadB64 || !sigB64 || rest.length > 0) {
    throw new StateSignatureError("token must be payload.signature");
  }

  const expectedSig = base64urlDecode(sigB64);
  let matched = false;
  for (const secret of usable) {
    const candidate = hmac(payloadB64, secret);
    if (candidate.length === expectedSig.length && timingSafeEqual(candidate, expectedSig)) {
      matched = true;
      break;
    }
  }
  if (!matched) throw new StateSignatureError("signature mismatch");

  let parsed: unknown;
  try {
    parsed = JSON.parse(base64urlDecode(payloadB64).toString("utf8"));
  } catch {
    throw new StateSignatureError("payload is not valid JSON");
  }
  if (!isPayload(parsed)) throw new StateSignatureError("payload missing required fields");

  const ageSeconds = Math.floor(now() / 1000) - parsed.iat;
  if (ageSeconds < -60) {
    // Clock skew tolerance: more than a minute in the future = bogus.
    throw new StateSignatureError("payload issued in the future");
  }
  if (!options.skipTtl && ageSeconds > STATE_TTL_SECONDS) {
    throw new StateSignatureError(`expired (age ${ageSeconds}s > ${STATE_TTL_SECONDS}s)`);
  }

  return parsed;
}

function isPayload(v: unknown): v is SignedStatePayload {
  if (!v || typeof v !== "object") return false;
  const o = v as Record<string, unknown>;
  return (
    typeof o.userId === "number" &&
    Number.isInteger(o.userId) &&
    o.userId > 0 &&
    typeof o.redirectUri === "string" &&
    o.redirectUri.length > 0 &&
    typeof o.iat === "number" &&
    Number.isFinite(o.iat)
  );
}
