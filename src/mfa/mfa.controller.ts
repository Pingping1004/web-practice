import { Controller, Req, Res, Body, Post, Get, UseGuards, BadRequestException, NotFoundException, UnauthorizedException } from "@nestjs/common";
import { MfaService } from "./mfa.service";
import { Public } from "src/auth/decorator/public.decorator";
import { UserService } from "src/users/users.service";
import { PendingTokenGuard } from "src/auth/guard/pending-token.guard";
import { UserDeviceService } from "src/userDevice/userDevice.service";
import * as session from 'src/types/session';
import type { Request, Response } from "express";
import { LoggingService } from "src/logging/logging.service";

@Controller('auth/mfa')
export class MfaController {
    constructor(
        private readonly mfaService: MfaService,
        private readonly userService: UserService,
        private readonly userDeviceService: UserDeviceService,
        private readonly logger: LoggingService,
    ) { }

    @Public()
    @Get('setup')
    @UseGuards(PendingTokenGuard)
    async setupMfa(@Req() req: session.RequestWithUser) {
        const pendingToken = req.cookies?.pending_token;
        if (!pendingToken) throw new NotFoundException('No pending token for MFA');

        const { sub: userId } = await this.mfaService.verifyPendingToken(pendingToken);
        if (!userId) throw new NotFoundException('Invalid or expiring pending token');

        const user = await this.userService.findUserByUserId(userId);
        if (user.mfaEnabled && user.mfaSecret) {
            return {
                redirect: '/auth/mfa/verify',
                pendingToken,
            };
        }

        const mfaSecret = await this.mfaService.generateMfaSecret(userId);
        const { base32, otpauthUrl, qrCodeUrl } = mfaSecret;
        return { base32, otpauthUrl, qrCodeUrl, pendingToken };
    }

    @Public()
    @Post('verify')
    @UseGuards(PendingTokenGuard)
    async verifyMfa(
        @Req() req: session.RequestWithUser,
        @Body('totp') totp: string,
        @Res() res: Response
    ) {
        const ip = req.ip;
        const userAgent = req.headers['user-agent'];

        const deviceId = req.cookies['deviceId'];
        if (!deviceId) throw new BadRequestException(`Missing deviceId`);

        if (!userAgent || !ip) throw new NotFoundException('user agent or user IP not found');

        const userId = req.user?.sub;
        this.logger.log(`User agent for MFA verify: ${userAgent}`);
        if (!userId || !totp) throw new NotFoundException('userId or Totp for MFA not found');

        try {
            const userDevice = await this.userDeviceService.findUserDevice(userId, deviceId);
            if (!userDevice) throw new NotFoundException('User device for MFA verify not found');
            await this.mfaService.validateTotp(userId, totp);

            const { accessToken, refreshToken } = await this.mfaService.generateFinalToken(userId, true, ip, userAgent, deviceId, userDevice?.userDeviceId);

            res.cookie('access_token', accessToken, {
                httpOnly: true,
                secure: process.env.NODE_ENV === 'production',
                sameSite: 'lax',
                maxAge: 30 * 60 * 1000,
            });

            res.cookie('refresh_token', refreshToken, {
                httpOnly: true,
                secure: process.env.NODE_ENV === 'production',
                sameSite: 'lax',
                maxAge: 30 * 24 * 60 * 60 * 1000,
            });

            res.clearCookie('pending_token');
            return res.redirect('/users/profile');
        } catch (error) {
            this.logger.error('Failed to verify TOTP: ', error.message);
            throw new UnauthorizedException('Invalid TOTP code');
        }
    }
}

