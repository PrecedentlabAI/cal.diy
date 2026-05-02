import { EventTypesModule_2024_06_14 } from "@/platform/event-types/event-types_2024_06_14/event-types.module";
import { PrismaModule } from "@/modules/prisma/prisma.module";
import { TokensModule } from "@/modules/tokens/tokens.module";
import { UsersController } from "@/modules/users/users.controller";
import { UsersService } from "@/modules/users/services/users.service";
import { UsersRepository } from "@/modules/users/users.repository";
import { Module } from "@nestjs/common";

@Module({
  imports: [PrismaModule, EventTypesModule_2024_06_14, TokensModule],
  controllers: [UsersController],
  providers: [UsersRepository, UsersService],
  exports: [UsersRepository, UsersService],
})
export class UsersModule {}
