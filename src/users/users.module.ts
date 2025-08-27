import { Module } from '@nestjs/common';
import { UsersController } from './users.controller';
import { userService } from './users.service';
import { OauthModule } from 'src/oauth/oauth.module';
import { PrismaModule } from 'prisma/prisma.module';

@Module({
  imports: [
    OauthModule,
    PrismaModule
  ],
  controllers: [UsersController],
  providers: [userService],
  exports: [userService],
})
export class UsersModule {}
