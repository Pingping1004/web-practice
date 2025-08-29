import { BadRequestException, Body, Controller, Post } from "@nestjs/common";
import { PasswordService } from "./password.service";
import { RequestResetPassDto, ResetPassDto } from "./dto/password.dto";

@Controller('auth/password')
export class PasswordController {
    constructor(
        private readonly passwordService: PasswordService
    ) { }

    @Post('forgot')
    async requestPasswordReset(@Body() dto: RequestResetPassDto) {
        await this.passwordService.requestPasswordReset(dto.email);
        return { message: 'Email with reset token is already sent, please use this token to verify when reseting password' };
    }

    @Post('reset')
    async resetPassword(@Body() dto: ResetPassDto) {
        await this.passwordService.resetPassword(dto.resetToken, dto.newPassword);
        return { message: 'Successfully reset password' };
    }
}