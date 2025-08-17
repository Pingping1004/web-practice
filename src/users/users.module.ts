import { Module } from '@nestjs/common';
import { UsersController } from './users.controller';
import { UsersService } from './users.service';
import { OauthModule } from 'src/oauth/oauth.module';
import { PrismaModule } from 'prisma/prisma.module';

@Module({
  imports: [
    OauthModule,
    PrismaModule
  ],
  controllers: [UsersController],
  providers: [UsersService],
  exports: [UsersService],
})
export class UsersModule {}
