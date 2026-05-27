import {
  BadRequestException,
  Controller,
  ForbiddenException,
  Get,
  HttpCode,
  HttpStatus,
  Logger,
  NotFoundException,
  Post,
  Query,
  Redirect,
  UseGuards,
} from "@nestjs/common";
import { ConfigService } from "@nestjs/config";
import { ApiExcludeController } from "@nestjs/swagger";
import { calendar_v3 } from "@googleapis/calendar";
import { OAuth2Client } from "googleapis-common";
import { z } from "zod";

import { API_VERSIONS_VALUES } from "@/lib/api-versions";
import { ApiAuthGuardOnlyAllow } from "@/modules/auth/decorators/api-auth-guard-only-allow.decorator";
import { GetUser } from "@/modules/auth/decorators/get-user/get-user.decorator";
import { ApiAuthGuard } from "@/modules/auth/guards/api-auth/api-auth.guard";
import type { ApiAuthGuardUser } from "@/modules/auth/strategies/api-auth/api-auth.strategy";
import { AppsRepository } from "@/modules/apps/apps.repository";
import { CalendarsService } from "@/platform/calendars/services/calendars.service";
import { GoogleMeetService } from "@/modules/conferencing/services/google-meet.service";
import { SelectedCalendarsRepository } from "@/modules/selected-calendars/selected-calendars.repository";
import { emitCredentialAttached } from "@/modules/pl-oauth/webhook-emitter";
import type { WebhookConfig } from "@/modules/pl-oauth/webhook-emitter";
import { PrismaReadService } from "@/modules/prisma/prisma-read.service";
import {
  signState,
  StateSignatureError,
  verifyState,
} from "@/modules/pl-oauth/state-signer";

import { GOOGLE_CALENDAR_TYPE, SUCCESS_STATUS } from "@calcom/platform-constants";
import { Prisma } from "@calcom/prisma/client";

/**
 * Admin-authed OAuth provisioning routes for PL platform integration.
 *
 * The standard cal.diy calendar OAuth routes (/v2/calendars/<type>/connect)
 * require a per-user Bearer access token (cal.com NextAuth/Platform OAuth,
 * NOT an API key — confirmed in tokens.repository.ts:158). pl-api drives
 * provisioning from an admin API key and identifies the practitioner by
 * their cal.diy numeric userId. This controller wraps the OAuth machinery
 * so pl-api stays admin-key-only.
 *
 * Routes:
 *   GET /v2/oauth/connect/google-calendar?userId=N&redirectUri=URL
 *     → { status, data: { authUrl } }
 *     The state= passed to Google is HMAC-SHA256-signed (state-signer.ts)
 *     so a tampered userId fails verification on /save.
 *
 *   GET /v2/oauth/save/google-calendar?state=...&code=...
 *     OAuth callback. Verifies the signed state, exchanges code → tokens,
 *     dedupes against any existing Credential row for (userId,
 *     google_calendar), saves/updates atomically, then synchronously
 *     attaches Google Meet, then fires CREDENTIAL_ATTACHED webhooks
 *     to pl-api for each successful credential. 301s the browser back to
 *     the pl-web-supplied redirectUri with ?google=connected.
 *
 *   POST /v2/oauth/connect/google-meet?userId=N
 *     Standalone Meet attach. Kept for backfill / manual repair paths;
 *     the happy-path Calendar OAuth already attaches Meet synchronously.
 *
 * The OAuth client's Google Console "Authorized redirect URIs" must
 * include `${api.url}/v2/oauth/save/google-calendar`.
 */

const CALENDAR_SCOPES = [
  "https://www.googleapis.com/auth/calendar.readonly",
  "https://www.googleapis.com/auth/calendar.events",
];

const statePayloadSchema = z.object({
  userId: z.number().int().positive(),
  redirectUri: z.string().url(),
});

const credentialsSchema = z.object({
  client_id: z.string(),
  client_secret: z.string(),
});

@Controller({
  path: "/v2/oauth",
  version: API_VERSIONS_VALUES,
})
@ApiExcludeController(true)
export class PlOAuthController {
  private readonly logger = new Logger("PlOAuthController");

  constructor(
    private readonly config: ConfigService,
    private readonly appsRepository: AppsRepository,
    private readonly calendarsService: CalendarsService,
    private readonly googleMeetService: GoogleMeetService,
    private readonly prismaRead: PrismaReadService,
    private readonly selectedCalendarsRepository: SelectedCalendarsRepository,
  ) {}

  private get googleSaveRedirectUri(): string {
    return `${this.config.get("api.url")}/oauth/save/google-calendar`;
  }

  private get stateSigningKey(): string {
    const key = this.config.get<string>("plOAuth.stateHmacKey");
    if (!key) {
      // Fail closed: if the operator hasn't configured the key, refuse to
      // sign anything rather than silently emitting unsigned state.
      throw new Error(
        "CALCOM_OAUTH_STATE_HMAC_KEY not configured — /v2/oauth/connect cannot sign state",
      );
    }
    return key;
  }

  private get stateVerifyingKeys(): string[] {
    const keys: string[] = [];
    const primary = this.config.get<string>("plOAuth.stateHmacKey");
    if (primary) keys.push(primary);
    const previous = this.config.get<string>("plOAuth.stateHmacKeyPrevious");
    if (previous) keys.push(previous);
    return keys;
  }

  private get outboundWebhookConfig(): WebhookConfig | undefined {
    const url = this.config.get<string>("plOAuth.webhookUrl");
    const secret = this.config.get<string>("plOAuth.webhookSecret");
    if (!url || !secret) return undefined;
    return { url, secret };
  }

  /**
   * Initiate Google Calendar OAuth for a specific cal.diy user. Admin-authed.
   * Returns the Google consent URL; pl-web redirects the practitioner there.
   * The state= param is HMAC-signed so /save can prove the userId wasn't
   * tampered with on the round-trip.
   */
  @Get("/connect/google-calendar")
  @HttpCode(HttpStatus.OK)
  @UseGuards(ApiAuthGuard)
  @ApiAuthGuardOnlyAllow(["API_KEY"])
  async connectGoogleCalendar(
    @Query("userId") userIdRaw: string,
    @Query("redirectUri") redirectUri: string,
    @GetUser() authUser: ApiAuthGuardUser,
  ): Promise<{ status: typeof SUCCESS_STATUS; data: { authUrl: string } }> {
    this._assertSystemAdmin(authUser);
    const userId = parseInt(userIdRaw ?? "", 10);
    if (!Number.isFinite(userId) || userId <= 0) {
      throw new BadRequestException("userId query param required and must be a positive integer");
    }
    if (!redirectUri || !/^https?:\/\//.test(redirectUri)) {
      throw new BadRequestException("redirectUri query param required and must be a valid http(s) URL");
    }

    const user = await this.prismaRead.prisma.user.findUnique({ where: { id: userId } });
    if (!user) {
      throw new NotFoundException(`cal.diy user ${userId} not found`);
    }

    const oAuth2Client = await this.getGoogleOAuthClient();
    const signedState = signState({ userId, redirectUri }, this.stateSigningKey);
    const authUrl = oAuth2Client.generateAuthUrl({
      access_type: "offline",
      scope: CALENDAR_SCOPES,
      prompt: "consent",
      state: signedState,
    });

    return { status: SUCCESS_STATUS, data: { authUrl } };
  }

  /**
   * OAuth callback. Google redirects here after the user consents.
   * Sequence:
   *   1. Verify HMAC signature on state — rejects tampered userId.
   *   2. If user cancelled (no code), 301 back with ?google=cancelled.
   *   3. Exchange code → tokens, fetch primary calendar id.
   *   4. Look up existing Credential row to dedupe — pass its id to
   *      createAndLinkCalendarEntry so the upsert UPDATES instead of
   *      inserting a duplicate (the underlying repo upserts on Credential.id;
   *      passing undefined always creates).
   *   5. Synchronously attach Google Meet — collapse the two credentials
   *      into one cal.diy-side completion event. If Meet fails for a real
   *      reason (not "already connected"), log and continue: the Calendar
   *      credential alone is still useful and we don't want to roll back
   *      a successful Calendar save.
   *   6. Fire CREDENTIAL_ATTACHED webhooks to pl-api (best-effort,
   *      reconciler catches misses).
   *   7. 301 the browser back to pl-web's redirectUri with ?google=connected.
   *
   * No auth guard — Google can't carry our admin key. Trust comes from
   * the HMAC-signed state combined with Google's single-use code.
   */
  @Get("/save/google-calendar")
  @Redirect(undefined, 301)
  async saveGoogleCalendar(
    @Query("state") rawState: string,
    @Query("code") code: string,
    @Query("error") errorParam?: string,
  ): Promise<{ url: string }> {
    // 1. Verify signature + parse payload. Signature is required even
    //    on user-cancel so an attacker can't craft a state that
    //    redirects to attacker.com. TTL is relaxed for the cancel
    //    branch because users can sit on the Google consent screen
    //    longer than STATE_TTL_SECONDS — Codex pass-8 P3.
    const isCancel = Boolean(errorParam) || !code;
    let payload: { userId: number; redirectUri: string };
    try {
      const verified = verifyState(rawState, this.stateVerifyingKeys, Date.now, {
        skipTtl: isCancel,
      });
      payload = statePayloadSchema.parse({
        userId: verified.userId,
        redirectUri: verified.redirectUri,
      });
    } catch (err) {
      const reason = err instanceof StateSignatureError ? err.message : `state parse: ${err}`;
      this.logger.warn(`save/google-calendar: ${reason}`);
      throw new BadRequestException("invalid state");
    }

    // 2. User clicked "Cancel" on the Google consent screen.
    if (isCancel) {
      const url = new URL(payload.redirectUri);
      url.searchParams.set("google", "cancelled");
      return { url: url.toString() };
    }

    // 3. Exchange code → tokens and find primary calendar.
    const oAuth2Client = await this.getGoogleOAuthClient();
    const { tokens } = await oAuth2Client.getToken(code);
    oAuth2Client.setCredentials(tokens);

    const calendar = new calendar_v3.Calendar({ auth: oAuth2Client });
    const cals = await calendar.calendarList.list({ fields: "items(id,summary,primary,accessRole)" });
    const primary = cals.data.items?.find((c) => c.primary);
    if (!primary?.id) {
      this.logger.error(`save/google-calendar: user ${payload.userId} has no primary calendar`);
      throw new BadRequestException("no primary calendar found");
    }

    // 4. Dedupe by the SelectedCalendar that points at THIS Google
    //    primary calendar — not by an arbitrary "any google_calendar
    //    credential for this user". Codex pass-2 review caught this:
    //    if a user already has multiple google_calendar credentials
    //    from the old broken-dedupe path, findFirst could return an
    //    unrelated one and we'd silently overwrite it, redirecting
    //    other SelectedCalendar rows at the new Google account.
    //
    //    Keying on externalId=primary.id only reuses the Credential
    //    that previously owned this exact Google account. Reconnecting
    //    a DIFFERENT Google account returns null and we create a fresh
    //    Credential — no cross-pollination.
    const existingSelected = await this.selectedCalendarsRepository.getUserSelectedCalendar(
      payload.userId,
      GOOGLE_CALENDAR_TYPE,
      primary.id,
    );
    await this.calendarsService.createAndLinkCalendarEntry(
      payload.userId,
      primary.id,
      tokens as Prisma.InputJsonValue,
      GOOGLE_CALENDAR_TYPE,
      existingSelected?.credentialId ?? null,
    );

    // 5. Attach Google Meet synchronously. cal.com guards via "already
    //    connected" BadRequestException — treat that as success. Any
    //    other failure: log, leave Calendar intact, continue.
    //
    //    Known race for users with legacy duplicate google_calendar
    //    Credentials: connectGoogleMeetToUser validates via an unordered
    //    findFirst that doesn't filter on `invalid`, so it can pick a
    //    stale row and throw "requires a valid Google Calendar
    //    connection". We accept this — the catch block logs the failure
    //    so ops can spot affected users, and the standalone
    //    /v2/oauth/connect/google-meet route or Deploy D's reconciler
    //    backfills Meet later. C-9 SQL cleanup removes the duplicates
    //    permanently. We can't classify duplicates safely here because
    //    a legitimate multi-account user also has >1 credential. Codex
    //    pass-7 P2.
    let meetAttached = false;
    try {
      await this.googleMeetService.connectGoogleMeetToUser(payload.userId);
      meetAttached = true;
    } catch (err) {
      const msg = err instanceof Error ? err.message : String(err);
      if (/already connected/i.test(msg)) {
        meetAttached = true;
      } else {
        this.logger.warn(
          `save/google-calendar: Meet attach failed for user ${payload.userId}: ${msg}`,
        );
      }
    }

    // 6. Webhooks to pl-api. Awaited so Cloud Run doesn't drop the
    //    in-flight fetch when the instance scales down after returning
    //    the redirect. The emitter has an internal 3s AbortController
    //    timeout, so worst-case the redirect is delayed by ~3s per
    //    pending webhook — acceptable bound. Codex pass-8 P2.
    const webhookConfig = this.outboundWebhookConfig;
    await emitCredentialAttached(webhookConfig, {
      userId: payload.userId,
      type: "google_calendar",
    }).catch((err) => {
      this.logger.warn(
        `CREDENTIAL_ATTACHED google_calendar webhook unexpectedly threw: ${
          err instanceof Error ? err.message : err
        }`,
      );
      return false;
    });
    if (meetAttached) {
      await emitCredentialAttached(webhookConfig, {
        userId: payload.userId,
        type: "google_meet",
      }).catch((err) => {
        this.logger.warn(
          `CREDENTIAL_ATTACHED google_meet webhook unexpectedly threw: ${
            err instanceof Error ? err.message : err
          }`,
        );
        return false;
      });
    }

    // 7. Browser hand-off back to pl-web.
    const url = new URL(payload.redirectUri);
    url.searchParams.set("google", "connected");
    return { url: url.toString() };
  }

  /**
   * Admin-authed Google Meet credential creation. Kept as a standalone
   * route for backfill paths and manual repair. The happy-path Calendar
   * OAuth in saveGoogleCalendar already attaches Meet synchronously.
   *
   * Idempotent: returns 200 with already_connected=true if a Meet
   * credential already exists for the user.
   */
  @Post("/connect/google-meet")
  @HttpCode(HttpStatus.OK)
  @UseGuards(ApiAuthGuard)
  @ApiAuthGuardOnlyAllow(["API_KEY"])
  async connectGoogleMeet(
    @Query("userId") userIdRaw: string,
    @GetUser() authUser: ApiAuthGuardUser,
  ): Promise<{ status: typeof SUCCESS_STATUS; data: { connected: true; already_connected: boolean } }> {
    this._assertSystemAdmin(authUser);
    const userId = parseInt(userIdRaw ?? "", 10);
    if (!Number.isFinite(userId) || userId <= 0) {
      throw new BadRequestException("userId query param required and must be a positive integer");
    }

    const emitMeetAttached = () =>
      // Awaited so Cloud Run doesn't drop the in-flight fetch on scale-
      // down (codex pass-9 P2). Emitter has a 3s AbortController, so
      // the endpoint's worst-case latency goes up by ~3s — acceptable.
      // Emitted on BOTH the freshly-attached AND already-connected
      // branches so a repair call is never silently a no-op from
      // pl-api's perspective.
      emitCredentialAttached(this.outboundWebhookConfig, {
        userId,
        type: "google_meet",
      }).catch((err) => {
        this.logger.warn(
          `CREDENTIAL_ATTACHED google_meet (standalone) webhook unexpectedly threw: ${
            err instanceof Error ? err.message : err
          }`,
        );
        return false;
      });

    try {
      await this.googleMeetService.connectGoogleMeetToUser(userId);
      await emitMeetAttached();
      return { status: SUCCESS_STATUS, data: { connected: true, already_connected: false } };
    } catch (err) {
      const msg = err instanceof Error ? err.message : String(err);
      if (/already connected/i.test(msg)) {
        await emitMeetAttached();
        return { status: SUCCESS_STATUS, data: { connected: true, already_connected: true } };
      }
      throw err;
    }
  }

  /**
   * Gate the admin-only endpoints on user.isSystemAdmin (set by
   * ApiAuthStrategy from User.role === "ADMIN"). Without this check,
   * any cal.diy user with an API key could call POST
   * /v2/oauth/connect/google-meet?userId=<victim> and forge a
   * CREDENTIAL_ATTACHED event for another tenant via the
   * already-connected emit branch (codex pass-8 P1). Mirrors the
   * pattern in users.controller.ts.
   */
  private _assertSystemAdmin(authUser: ApiAuthGuardUser | undefined | null): void {
    if (!authUser?.isSystemAdmin) {
      throw new ForbiddenException("system admin auth required");
    }
  }

  private async getGoogleOAuthClient(): Promise<OAuth2Client> {
    const app = await this.appsRepository.getAppBySlug("google-calendar");
    if (!app) {
      throw new NotFoundException(
        "Google Calendar app is not installed in cal.diy. Insert an App row with slug='google-calendar' and keys={client_id, client_secret}.",
      );
    }
    const { client_id, client_secret } = credentialsSchema.parse(app.keys);
    return new OAuth2Client(client_id, client_secret, this.googleSaveRedirectUri);
  }
}
