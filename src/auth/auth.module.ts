import { forwardRef, Module } from '@nestjs/common';
import { AuthController } from './auth.controller';
import { AuthService } from './auth.service';
import { UsersModule } from 'src/users/users.module';
import { JwtModule } from '@nestjs/jwt';
import { jwtConstants } from './constant';
import { PassportModule } from '@nestjs/passport';
import { LocalStrategy } from './strategies/local.strategy';
import { JwtStrategy } from './strategies/jwt.strategy';
import { SessionModule } from 'src/session/session.module';
import { ConfigModule, ConfigService } from '@nestjs/config';
import { OauthModule } from 'src/oauth/oauth.module';
import { GoogleStrategy } from './strategies/google.strategy';
import { MfaModule } from 'src/mfa/mfa.module';
import { DeviceModule } from 'src/device/device.module';
import { UserDeviceModule } from 'src/userDevice/userDevice.module';

@Module({
  imports: [
    UsersModule,
    PassportModule,
    SessionModule,
    OauthModule,
    DeviceModule,
    UserDeviceModule,
    forwardRef(() => MfaModule),
    JwtModule.registerAsync({
      imports: [ConfigModule],
      useFactory: async () => ({
        secret: jwtConstants.secret,
        signOptions: { expiresIn: '30m' },
      }),
      inject: [ConfigService],
    }),
  ],
  controllers: [AuthController],
  providers: [AuthService, LocalStrategy, JwtStrategy, GoogleStrategy],
  exports: [AuthService],
})
export class AuthModule {}
