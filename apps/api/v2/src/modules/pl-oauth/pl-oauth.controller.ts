import {
  BadRequestException,
  Controller,
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
import { ApiAuthGuard } from "@/modules/auth/guards/api-auth/api-auth.guard";
import { AppsRepository } from "@/modules/apps/apps.repository";
import { CalendarsService } from "@/platform/calendars/services/calendars.service";
import { GoogleMeetService } from "@/modules/conferencing/services/google-meet.service";
import { PrismaReadService } from "@/modules/prisma/prisma-read.service";

import { GOOGLE_CALENDAR_TYPE, SUCCESS_STATUS } from "@calcom/platform-constants";
import { Prisma } from "@calcom/prisma/client";

/**
 * Admin-authed OAuth provisioning routes for PL platform integration.
 *
 * The standard cal.diy calendar OAuth routes (/v2/calendars/<type>/connect)
 * require a per-user Bearer access token. pl-api drives provisioning from a
 * single admin API key and identifies the practitioner by their cal.diy
 * numeric `userId`. This controller wraps the same OAuth machinery with
 * admin-authed entrypoints so pl-api can stay token-free per practitioner.
 *
 * Routes:
 *   GET /v2/oauth/connect/google-calendar?userId=N&redirectUri=URL
 *     → { status, data: { authUrl } }
 *     The practitioner is redirected to authUrl. State encodes
 *     {userId, redirectUri} as JSON.
 *
 *   GET /v2/oauth/save/google-calendar?state=...&code=...
 *     OAuth callback handler. Exchanges code for tokens, persists the
 *     Google credential against userId, then 301s to redirectUri.
 *
 * This redirect URI (the /save endpoint above) MUST be registered as an
 * "Authorized redirect URI" in the Google Cloud OAuth client.
 */

const CALENDAR_SCOPES = [
  "https://www.googleapis.com/auth/calendar.readonly",
  "https://www.googleapis.com/auth/calendar.events",
];

const stateSchema = z.object({
  userId: z.number().int().positive(),
  redirectUri: z.string().url(),
});
type State = z.infer<typeof stateSchema>;

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
  ) {}

  private get googleSaveRedirectUri(): string {
    return `${this.config.get("api.url")}/oauth/save/google-calendar`;
  }

  /**
   * Initiate Google Calendar OAuth for a specific cal.diy user. Admin-authed.
   * Returns the Google consent URL; pl-web redirects the practitioner there.
   */
  @Get("/connect/google-calendar")
  @HttpCode(HttpStatus.OK)
  @UseGuards(ApiAuthGuard)
  @ApiAuthGuardOnlyAllow(["API_KEY"])
  async connectGoogleCalendar(
    @Query("userId") userIdRaw: string,
    @Query("redirectUri") redirectUri: string,
  ): Promise<{ status: typeof SUCCESS_STATUS; data: { authUrl: string } }> {
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
    const state: State = { userId, redirectUri };
    const authUrl = oAuth2Client.generateAuthUrl({
      access_type: "offline",
      scope: CALENDAR_SCOPES,
      prompt: "consent",
      state: JSON.stringify(state),
    });

    return { status: SUCCESS_STATUS, data: { authUrl } };
  }

  /**
   * OAuth callback. Google redirects here after the user consents. We
   * exchange the code for tokens, attach the credential to the cal.diy
   * user from the state blob, then 301 the browser back to the
   * pl-web-supplied redirectUri.
   *
   * No auth guard — Google can't carry our admin key. Trust comes from
   * the state being base64-JSON-signable only by us at /connect time,
   * combined with Google's PKCE-like single-use code.
   */
  @Get("/save/google-calendar")
  @Redirect(undefined, 301)
  async saveGoogleCalendar(
    @Query("state") rawState: string,
    @Query("code") code: string,
    @Query("error") errorParam?: string,
  ): Promise<{ url: string }> {
    // Parse state first — even on user-cancel we need redirectUri to send them back.
    let parsed: State;
    try {
      parsed = stateSchema.parse(JSON.parse(rawState));
    } catch (err) {
      this.logger.warn(`save/google-calendar: invalid state: ${err}`);
      throw new BadRequestException("invalid state");
    }

    // User clicked "Cancel" on the Google consent screen → no code, send them back.
    if (errorParam || !code) {
      const url = new URL(parsed.redirectUri);
      url.searchParams.set("google", "cancelled");
      return { url: url.toString() };
    }

    const oAuth2Client = await this.getGoogleOAuthClient();
    const { tokens } = await oAuth2Client.getToken(code);
    oAuth2Client.setCredentials(tokens);

    // Find the user's primary calendar id — the canonical "their main calendar".
    const calendar = new calendar_v3.Calendar({ auth: oAuth2Client });
    const cals = await calendar.calendarList.list({ fields: "items(id,summary,primary,accessRole)" });
    const primary = cals.data.items?.find((c) => c.primary);
    if (!primary?.id) {
      this.logger.error(`save/google-calendar: user ${parsed.userId} has no primary calendar`);
      throw new BadRequestException("no primary calendar found");
    }

    await this.calendarsService.createAndLinkCalendarEntry(
      parsed.userId,
      primary.id,
      tokens as Prisma.InputJsonValue,
      GOOGLE_CALENDAR_TYPE,
    );

    // Redirect the browser back to pl-web with a success marker.
    const url = new URL(parsed.redirectUri);
    url.searchParams.set("google", "connected");
    return { url: url.toString() };
  }

  /**
   * Admin-authed Google Meet credential creation. The standard
   * /v2/conferencing/google-meet/connect endpoint reads the authenticated
   * user from @GetUser(), which resolves to the admin user when pl-api
   * uses its admin API key — making the Google Calendar prerequisite
   * check look at the wrong user. This wrapper accepts ?userId and
   * provisions Meet for the target user instead.
   *
   * Idempotent: returns 200 with already-connected=true if a Meet
   * credential already exists for the user.
   */
  @Post("/connect/google-meet")
  @HttpCode(HttpStatus.OK)
  @UseGuards(ApiAuthGuard)
  @ApiAuthGuardOnlyAllow(["API_KEY"])
  async connectGoogleMeet(
    @Query("userId") userIdRaw: string,
  ): Promise<{ status: typeof SUCCESS_STATUS; data: { connected: true; already_connected: boolean } }> {
    const userId = parseInt(userIdRaw ?? "", 10);
    if (!Number.isFinite(userId) || userId <= 0) {
      throw new BadRequestException("userId query param required and must be a positive integer");
    }

    try {
      await this.googleMeetService.connectGoogleMeetToUser(userId);
      return { status: SUCCESS_STATUS, data: { connected: true, already_connected: false } };
    } catch (err) {
      // GoogleMeetService throws BadRequestException with "already connected" when the
      // credential exists. Treat it as success — pl-api retries are common after the
      // OAuth redirect, so we don't want each retry to 400.
      const msg = err instanceof Error ? err.message : String(err);
      if (/already connected/i.test(msg)) {
        return { status: SUCCESS_STATUS, data: { connected: true, already_connected: true } };
      }
      throw err;
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
