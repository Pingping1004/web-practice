import { forwardRef, Module } from '@nestjs/common';
import { UsersController } from './users.controller';
import { UsersService } from './users.service';
import { PrismaService } from 'prisma/prisma.service';
import { OauthModule } from 'src/oauth/oauth.module';
import { MfaModule } from 'src/mfa/mfa.module';

@Module({
  imports: [
    OauthModule,
    forwardRef(() => MfaModule),
  ],
  controllers: [UsersController],
  providers: [UsersService, PrismaService],
  exports: [UsersService],
})
export class UsersModule {}
