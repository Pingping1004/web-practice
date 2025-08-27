import { Module } from "@nestjs/common";
import { ResetPassService } from "./resetPass.service";
import { PrismaModule } from "prisma/prisma.module";

@Module({
    imports: [PrismaModule],
    providers: [ResetPassService],
    exports: [ResetPassService],
})
export class ResetPassModule {}