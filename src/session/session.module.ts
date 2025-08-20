import { forwardRef, Module } from "@nestjs/common";
import { PrismaModule } from "prisma/prisma.module";
import { SessionService } from "./session.service";
import { MfaModule } from "src/mfa/mfa.module";

@Module({
    imports: [
        PrismaModule,
        forwardRef(() => MfaModule),
    ],
    providers: [SessionService],
    exports: [SessionService],
})
export class SessionModule {}