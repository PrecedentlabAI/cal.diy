import { SUCCESS_STATUS } from "@calcom/platform-constants";
import {
  BadRequestException,
  Body,
  Controller,
  ForbiddenException,
  HttpCode,
  HttpStatus,
  Logger,
  NotFoundException,
  Param,
  Post,
  UseGuards,
} from "@nestjs/common";
import { ApiHeader, ApiOperation, ApiTags } from "@nestjs/swagger";
import { randomBytes, randomUUID } from "node:crypto";
import { IsEmail, IsOptional, IsString, IsTimeZone, MaxLength } from "class-validator";
import { ConfigService } from "@nestjs/config";

import { API_VERSIONS_VALUES } from "@/lib/api-versions";
import { API_KEY_HEADER } from "@/lib/docs/headers";
import { sha256Hash } from "@/lib/api-key";
import { GetUser } from "@/modules/auth/decorators/get-user/get-user.decorator";
import { ApiAuthGuard } from "@/modules/auth/guards/api-auth/api-auth.guard";
import type { ApiAuthGuardUser } from "@/modules/auth/strategies/api-auth/api-auth.strategy";
import { PrismaWriteService } from "@/modules/prisma/prisma-write.service";
import { PrismaReadService } from "@/modules/prisma/prisma-read.service";

import { CreationSource } from "@calcom/platform-libraries";

class CreateUserInput {
  @IsEmail()
  email!: string;

  @IsString()
  name!: string;

  @IsTimeZone()
  @IsOptional()
  timeZone?: string;
}

class CreateApiKeyInput {
  @IsString()
  @MaxLength(255)
  @IsOptional()
  note?: string;
}

/**
 * PrecedentLab fork addition. Wraps cal.com user creation with admin auth
 * and ALSO mints a never-expiring API key for the new user — pl-api needs
 * a per-user bearer token to call cal.com's user-scoped endpoints that
 * resolve the target user from @GetUser() (event-types, slots, bookings,
 * google-meet/connect, calendar /check).
 *
 * cal.com's stock ApiKeysService.createApiKey delegates to
 * createApiKeyHandler in @calcom/platform-libraries, which is stubbed
 * (EE-only feature). We do the raw insert instead — same shape the
 * scripts/seed-pl-admin.js admin seed uses.
 *
 * The plaintext key is returned ONCE in the create response. There is no
 * way to retrieve it again — pl-api must store it on receipt.
 */
@Controller({
  path: "/v2/users",
  version: API_VERSIONS_VALUES,
})
@UseGuards(ApiAuthGuard)
@ApiTags("Users")
@ApiHeader(API_KEY_HEADER)
export class UsersController {
  private readonly logger = new Logger("UsersController");

  constructor(
    private readonly dbWrite: PrismaWriteService,
    private readonly dbRead: PrismaReadService,
    private readonly config: ConfigService,
  ) {}

  @Post("/")
  @HttpCode(HttpStatus.CREATED)
  @ApiOperation({ summary: "Create a cal.diy user + mint per-user API key (admin auth required)" })
  async createUser(@Body() body: CreateUserInput, @GetUser() authUser: ApiAuthGuardUser) {
    this._assertSystemAdmin(authUser);
    const existing = await this.dbRead.prisma.user.findUnique({ where: { email: body.email } });
    if (existing) {
      // Re-provision case. Don't rotate the key here — that would
      // invalidate whatever pl-api has stored. pl-api backfills via
      // POST /v2/users/:id/api-keys (Slice C-2) when a CalcomLink has
      // a NULL key.
      return {
        status: SUCCESS_STATUS,
        data: {
          user: {
            id: existing.id,
            username: existing.username ?? "",
            email: existing.email,
            timeZone: existing.timeZone,
          },
          apiKey: null,
        },
      };
    }

    const baseUsername = body.email.split("@")[0].toLowerCase().replace(/[^a-z0-9-]/g, "-");
    const username = await this._uniqueUsername(baseUsername);

    const user = await this.dbWrite.prisma.user.create({
      data: {
        email: body.email,
        name: body.name,
        username,
        timeZone: body.timeZone ?? "Europe/London",
        completedOnboarding: true,
        creationSource: CreationSource.API_V2,
      },
    });

    // Mint a never-expiring per-user API key. Wrap in try/except so a key
    // failure doesn't fail user creation — pl-api can backfill via the
    // admin endpoint.
    let apiKey: string | null = null;
    try {
      apiKey = await this._mintApiKey(user.id, "PrecedentLab pl-api per-tenant key");
    } catch (err) {
      this.logger.error(
        `Failed to mint API key for user ${user.id}: ${err instanceof Error ? err.message : err}`,
      );
    }

    return {
      status: SUCCESS_STATUS,
      data: {
        user: {
          id: user.id,
          username: user.username ?? "",
          email: user.email,
          timeZone: user.timeZone,
        },
        apiKey,
      },
    };
  }

  /**
   * Mint a new API key for an EXISTING cal.diy user. Backfill path for
   * CalcomLink rows whose calcom_user_api_key column is empty (rows
   * created before the C-1 minting endpoint shipped, or any row where
   * the create-user response returned apiKey=null because the user
   * already existed). Admin auth only.
   *
   * Idempotency: this endpoint MINTS A NEW KEY every call. cal.com's
   * ApiKey table allows multiple unexpired keys per user, so repeated
   * calls don't break, but the caller is responsible for not re-minting
   * once it has a working key. pl-api's backfill command checks for a
   * blank column before calling.
   */
  @Post("/:userId/api-keys")
  @HttpCode(HttpStatus.CREATED)
  @ApiOperation({ summary: "Mint a new API key for an existing cal.diy user (admin auth required)" })
  async createApiKeyForUser(
    @Param("userId") userIdRaw: string,
    @Body() body: CreateApiKeyInput,
    @GetUser() authUser: ApiAuthGuardUser,
  ) {
    this._assertSystemAdmin(authUser);

    const userId = parseInt(userIdRaw, 10);
    if (!Number.isFinite(userId) || userId <= 0) {
      throw new BadRequestException("userId path param must be a positive integer");
    }

    const user = await this.dbRead.prisma.user.findUnique({ where: { id: userId } });
    if (!user) {
      throw new NotFoundException(`cal.diy user ${userId} not found`);
    }

    // NestJS instantiates the DTO for empty/missing bodies (all fields
    // optional), so `body` is at minimum `{}` here — `?.trim()` plus the
    // `||` fallback safely handles both the no-body and explicit-note
    // cases. The concrete DTO type preserves class-validator's runtime
    // checks (a union with `undefined` collapses to `Object` and skips
    // validation; codex pass-6 P2).
    const note = body.note?.trim() || "PrecedentLab pl-api per-tenant key (backfill)";
    const apiKey = await this._mintApiKey(userId, note);

    return {
      status: SUCCESS_STATUS,
      data: {
        userId,
        apiKey,
      },
    };
  }

  /**
   * Gate both endpoints on the cal.diy system-admin user. ApiAuthGuard
   * only proves the bearer is valid — it doesn't say WHICH user. Without
   * this check, any cal.diy user with an API key (which is anyone, since
   * users can mint their own via the standard /api-keys route) could
   * call POST /v2/users/:otherUserId/api-keys and walk away with a
   * plaintext never-expiring key for another account. Codex caught this
   * on review 2026-05-19.
   *
   * isSystemAdmin is populated by ApiAuthStrategy from User.role === "ADMIN"
   * (api-auth.strategy.ts:162). The PL admin seed sets that role for the
   * single user pl-api authenticates as.
   */
  private _assertSystemAdmin(authUser: ApiAuthGuardUser | undefined | null): void {
    if (!authUser?.isSystemAdmin) {
      throw new ForbiddenException("system admin auth required");
    }
  }

  /**
   * Insert an ApiKey row directly via Prisma. Mirrors the pattern in
   * scripts/seed-pl-admin.js — cal.com's EE handler is stubbed so we
   * own this code path.
   *
   * Returns the plaintext key with the prefix attached. Caller MUST
   * surface this once and never log it.
   */
  private async _mintApiKey(userId: number, note: string): Promise<string> {
    const prefix = this.config.get<string>("api.keyPrefix") ?? "cal_";
    const secret = randomBytes(32).toString("hex"); // 64-char hex, ~256 bits entropy
    const hashedKey = sha256Hash(secret);
    const plaintext = `${prefix}${secret}`;

    await this.dbWrite.prisma.apiKey.create({
      data: {
        id: randomUUID(),
        userId,
        hashedKey,
        note,
        expiresAt: null, // never expire — pl-api is the only consumer
      },
    });

    return plaintext;
  }

  private async _uniqueUsername(base: string): Promise<string> {
    let candidate = base;
    let suffix = 1;
    while (true) {
      const existing = await this.dbRead.prisma.user.findFirst({ where: { username: candidate } });
      if (!existing) return candidate;
      candidate = `${base}-${suffix++}`;
    }
  }
}
