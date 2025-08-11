import { Module } from "@nestjs/common";
import { PrismaModule } from "prisma/prisma.module";
import { OauthService } from "./oauth.service";

@Module({
    imports: [PrismaModule],
    providers: [OauthService],
    exports: [OauthService],
})
export class OauthModule {}