import { SUCCESS_STATUS } from "@calcom/platform-constants";
import { Body, Controller, HttpCode, HttpStatus, Post, UseGuards } from "@nestjs/common";
import { ApiHeader, ApiOperation, ApiTags } from "@nestjs/swagger";
import { IsEmail, IsOptional, IsString, IsTimeZone } from "class-validator";
import { API_VERSIONS_VALUES } from "@/lib/api-versions";
import { API_KEY_HEADER } from "@/lib/docs/headers";
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

@Controller({
  path: "/v2/users",
  version: API_VERSIONS_VALUES,
})
@UseGuards(ApiAuthGuard)
@ApiTags("Users")
@ApiHeader(API_KEY_HEADER)
export class UsersController {
  constructor(
    private readonly dbWrite: PrismaWriteService,
    private readonly dbRead: PrismaReadService
  ) {}

  @Post("/")
  @HttpCode(HttpStatus.CREATED)
  @ApiOperation({ summary: "Create a cal.diy user (admin API key required)" })
  async createUser(@Body() body: CreateUserInput) {
    const existing = await this.dbRead.prisma.user.findUnique({ where: { email: body.email } });
    if (existing) {
      return {
        status: SUCCESS_STATUS,
        data: {
          user: {
            id: existing.id,
            username: existing.username ?? "",
            email: existing.email,
            timeZone: existing.timeZone,
          },
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

    return {
      status: SUCCESS_STATUS,
      data: {
        user: {
          id: user.id,
          username: user.username ?? "",
          email: user.email,
          timeZone: user.timeZone,
        },
      },
    };
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
