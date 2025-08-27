import { forwardRef, Module } from "@nestjs/common";
import { PrismaModule } from "prisma/prisma.module";
import { SessionService } from "./session.service";
import { MfaModule } from "src/mfa/mfa.module";
import { UserDeviceModule } from "src/userDevice/userDevice.module";

@Module({
    imports: [
        PrismaModule,
        UserDeviceModule,
        forwardRef(() => MfaModule),
    ],
    providers: [SessionService],
    exports: [SessionService],
})
export class SessionModule {}