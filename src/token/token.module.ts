import { Module } from "@nestjs/common";
import { PrismaModule } from "prisma/prisma.module";
import { SessionService } from "./token.service";

@Module({
    imports: [PrismaModule],
    providers: [SessionService],
    exports: [SessionService],
})
export class SessionModule {}