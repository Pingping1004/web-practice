import { Module } from "@nestjs/common";
import { ResetPassService } from "./resetPass.service";
import { PrismaModule } from "prisma/prisma.module";
import { UsersModule } from "src/users/users.module";

@Module({
    imports: [PrismaModule, UsersModule],
    providers: [ResetPassService],
    exports: [ResetPassService],
})
export class ResetPassModule {}