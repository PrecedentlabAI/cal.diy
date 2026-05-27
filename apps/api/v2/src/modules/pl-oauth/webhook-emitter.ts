import { createHmac, randomUUID } from "node:crypto";
import { Logger } from "@nestjs/common";

/**
 * Outbound webhook emitter for the PL OAuth wrapper. After a successful
 * Google Calendar (and/or Google Meet) credential attach inside the
 * /v2/oauth/save handler, fire CREDENTIAL_ATTACHED to pl-api so it can
 * flip CalcomLink.calendar_credential_valid synchronously instead of
 * relying on the frontend to race a second POST.
 *
 * Wire format:
 *
 *   Header: X-Cal-Signature-256: sha256=<hex>
 *           — HMAC-SHA256(secret, raw body), hex-encoded, with "sha256="
 *           prefix.
 *
 *   Body:   {
 *             "triggerEvent": "CREDENTIAL_ATTACHED",
 *             "createdAt":    "2026-05-19T18:00:00.000Z",
 *             "payload":      { "userId": N, "type": "google_calendar" }
 *           }
 *           — pl-api dedupes via (provider, event_id); event_id is
 *           derived from payload.uid + createdAt, so we include a
 *           UUID as `uid` and an ISO timestamp.
 *
 * Signature-format note: cal.com's canonical format
 * (packages/features/webhooks/lib/sendPayload.ts:createWebhookSignature)
 * is the raw hex digest with NO prefix. pl-api's existing verifier at
 * booking/webhooks/calcom.py:57 REQUIRES the "sha256=" prefix. To keep
 * Deploy A forward-compatible with pl-api today, we emit the prefixed
 * form here. Deploy B will make pl-api's verifier accept BOTH the
 * prefixed and canonical forms, after which we can switch to the
 * canon and be aligned with the cal.com ecosystem long-term.
 *
 * Best-effort: a failure here does NOT roll back the Calendar credential.
 * The reconciler (C-10) catches missed events on its next hourly tick.
 * Until Deploy B ships the CREDENTIAL_ATTACHED handler, pl-api will
 * accept the POST and return 200 with notes="unsupported event type" —
 * that's the intended forward-compat behavior.
 */

export type CredentialAttachedType = "google_calendar" | "google_meet";

export interface CredentialAttachedInput {
  userId: number;
  type: CredentialAttachedType;
}

interface WebhookBody {
  triggerEvent: "CREDENTIAL_ATTACHED";
  createdAt: string;
  payload: {
    uid: string;
    userId: number;
    type: CredentialAttachedType;
  };
}

export interface WebhookConfig {
  url: string; // pl-api inbound webhook endpoint, e.g. https://pl-api.../v1/webhooks/calcom/
  secret: string; // shared HMAC secret (matches pl-api's CALCOM_WEBHOOK_SECRET)
}

const logger = new Logger("PlOAuthWebhookEmitter");

/**
 * Best-effort POST. Returns true on 2xx, false otherwise. Never throws.
 */
export async function emitCredentialAttached(
  config: WebhookConfig | undefined,
  input: CredentialAttachedInput,
  now: () => number = Date.now,
  fetchFn: typeof fetch = fetch,
): Promise<boolean> {
  if (!config) {
    logger.debug(
      `CREDENTIAL_ATTACHED skipped (no webhook config): userId=${input.userId} type=${input.type}`,
    );
    return false;
  }
  if (!config.url || !config.secret) {
    logger.warn(
      `CREDENTIAL_ATTACHED skipped (url or secret missing): userId=${input.userId} type=${input.type}`,
    );
    return false;
  }

  const body: WebhookBody = {
    triggerEvent: "CREDENTIAL_ATTACHED",
    createdAt: new Date(now()).toISOString(),
    payload: {
      uid: randomUUID(),
      userId: input.userId,
      type: input.type,
    },
  };
  const rawBody = JSON.stringify(body);
  const signature = `sha256=${createHmac("sha256", config.secret).update(rawBody).digest("hex")}`;

  // Bounded latency: a slow pl-api must NOT block the OAuth redirect that
  // the practitioner's browser is waiting on. 3s is generous for a same-
  // region intra-VPC POST. If pl-api is slower than that, the reconciler
  // (C-10) picks up the credential on its next tick.
  const abortController = new AbortController();
  const timeoutHandle = setTimeout(() => abortController.abort(), 3000);

  try {
    const res = await fetchFn(config.url, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "X-Cal-Signature-256": signature,
      },
      body: rawBody,
      signal: abortController.signal,
    });
    if (!res.ok) {
      logger.warn(
        `CREDENTIAL_ATTACHED POST returned ${res.status}: userId=${input.userId} type=${input.type}`,
      );
      return false;
    }
    logger.log(`CREDENTIAL_ATTACHED delivered: userId=${input.userId} type=${input.type}`);
    return true;
  } catch (err) {
    const isAbort = err instanceof Error && err.name === "AbortError";
    logger.error(
      `CREDENTIAL_ATTACHED POST ${isAbort ? "timed out (3s)" : "failed"}: userId=${input.userId} type=${input.type}${
        isAbort ? "" : `: ${err instanceof Error ? err.message : err}`
      }`,
    );
    return false;
  } finally {
    clearTimeout(timeoutHandle);
  }
}
