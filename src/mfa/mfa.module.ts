import { forwardRef, Module } from "@nestjs/common";
import { MfaService } from "./mfa.service";
import { UsersModule } from "src/users/users.module";
import { JwtModule } from "@nestjs/jwt";
import { ConfigModule, ConfigService } from "@nestjs/config";
import { jwtConstants } from "src/auth/constant";
import { AuthModule } from "src/auth/auth.module";
import { SessionModule } from "src/session/session.module";
import { DeviceModule } from "src/device/device.module";

@Module({
    imports: [
        UsersModule,
        DeviceModule,
        forwardRef(() => AuthModule),
        forwardRef(() => SessionModule),
        JwtModule.registerAsync({
            imports: [ConfigModule],
            useFactory: async () => ({
                secret: jwtConstants.secret,
                signOptions: { expiresIn: '3m' },
            }),
            inject: [ConfigService],
        }),
    ],
    providers: [MfaService],
    exports: [MfaService],
})
export class MfaModule {}