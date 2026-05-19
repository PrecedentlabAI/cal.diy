import { SUCCESS_STATUS } from "@calcom/platform-constants";
import { Body, Controller, HttpCode, HttpStatus, Logger, Post, UseGuards } from "@nestjs/common";
import { ApiHeader, ApiOperation, ApiTags } from "@nestjs/swagger";
import { randomBytes, randomUUID } from "node:crypto";
import { IsEmail, IsOptional, IsString, IsTimeZone } from "class-validator";
import { ConfigService } from "@nestjs/config";

import { API_VERSIONS_VALUES } from "@/lib/api-versions";
import { API_KEY_HEADER } from "@/lib/docs/headers";
import { sha256Hash } from "@/lib/api-key";
import { ApiAuthGuard } from "@/modules/auth/guards/api-auth/api-auth.guard";
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
  async createUser(@Body() body: CreateUserInput) {
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
