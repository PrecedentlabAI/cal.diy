import { Module } from "@nestjs/common";

import { AppsRepository } from "@/modules/apps/apps.repository";
import { AuthModule } from "@/modules/auth/auth.module";
import { CalendarsModule } from "@/platform/calendars/calendars.module";
import { ConferencingModule } from "@/modules/conferencing/conferencing.module";
import { PlOAuthController } from "@/modules/pl-oauth/pl-oauth.controller";
import { PrismaModule } from "@/modules/prisma/prisma.module";
import { SelectedCalendarsModule } from "@/modules/selected-calendars/selected-calendars.module";

@Module({
  imports: [
    PrismaModule,
    AuthModule,
    CalendarsModule,
    ConferencingModule,
    SelectedCalendarsModule,
  ],
  controllers: [PlOAuthController],
  providers: [AppsRepository],
})
export class PlOAuthModule {}
