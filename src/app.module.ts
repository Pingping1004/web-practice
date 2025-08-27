import { Module } from '@nestjs/common';
import { AppController } from './app.controller';
import { AppService } from './app.service';
import { AuthModule } from './auth/auth.module';
import { UsersModule } from './users/users.module';
import { ConfigModule } from '@nestjs/config';
import { APP_GUARD } from '@nestjs/core';
import { JwtAuthGuard } from './auth/guard/jwt-auth.guard';
import { SessionModule } from './session/session.module';
import { OauthModule } from './oauth/oauth.module';
import { ThrottlerModule } from '@nestjs/throttler';
import { IpThrottlerGuard } from './auth/guard/ip-throttler.guard';
import { MfaModule } from './mfa/mfa.module';
import { DeviceModule } from './device/device.module';
import { UserDeviceModule } from './userDevice/userDevice.module';
import { ResetPassModule } from './resetPass/resetPass.module';

@Module({
  imports: [
    ConfigModule.forRoot({
      isGlobal: true,
      envFilePath: '.env',
    }),
    ThrottlerModule.forRoot({
      throttlers: [
        {
          ttl: 60,
          limit: 20,
        },
      ],
    }),
    AuthModule,
    UsersModule,
    SessionModule,
    OauthModule,
    MfaModule,
    DeviceModule,
    UserDeviceModule,
    ResetPassModule,
  ],
  controllers: [AppController],
  providers: [ 
    {
      provide: APP_GUARD,
      useClass: IpThrottlerGuard,
    },
    {
      provide: APP_GUARD,
      useClass: JwtAuthGuard,
    },
    AppService,
  ],
})
export class AppModule {}
