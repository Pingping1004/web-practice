import { Injectable } from "@nestjs/common";
import { UserService } from "src/users/users.service";

@Injectable()
export class ResetPassService {
    constructor(
        private readonly userService: UserService,
    ) {}
    async requestPasswordReset(email: string) {}

    async verifyResetToken(resetToken: string) {}

    async resetPassword(resetToken: string, newPassword: string) {}
}