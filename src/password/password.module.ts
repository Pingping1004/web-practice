import { Module } from "@nestjs/common";
import { PasswordService } from "./password.service";
import { PrismaModule } from "prisma/prisma.module";
import { UsersModule } from "src/users/users.module";
import { MailModule } from "src/mail/mail.module";
import { PasswordController } from "./passsword.controller";

@Module({
    imports: [
        PrismaModule,
         UsersModule,
         MailModule,
        ],
    providers: [PasswordService],
    controllers: [PasswordController],
    exports: [PasswordService],
})
export class PasswordModule {}