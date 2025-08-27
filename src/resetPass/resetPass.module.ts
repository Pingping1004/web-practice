import { Module } from "@nestjs/common";
import { ResetPassService } from "./resetPass.service";
import { PrismaModule } from "prisma/prisma.module";
import { UsersModule } from "src/users/users.module";
import { JwtModule } from "@nestjs/jwt";
import { ConfigModule, ConfigService } from "@nestjs/config";
import { jwtConstants } from "src/auth/constant";
import { MailModule } from "src/mail/mail.module";

@Module({
    imports: [
        PrismaModule,
         UsersModule,
         MailModule,
         JwtModule.registerAsync({
            imports: [ConfigModule],
            useFactory: async () => ({
                secret: jwtConstants.secret,
                signOptions: { expiresIn: '5m' },
            }),
            inject: [ConfigService],
         }),
        ],
    providers: [ResetPassService],
    exports: [ResetPassService],
})
export class ResetPassModule {}