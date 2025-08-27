import { Module } from "@nestjs/common";
import { UserDeviceService } from "./userDevice.service";
import { PrismaModule } from "prisma/prisma.module";

@Module({
    imports: [PrismaModule],
    providers: [UserDeviceService],
    exports: [UserDeviceService],
})
export class UserDeviceModule {}