import { BadRequestException, Body, Controller, Get, NotFoundException, Post, Req, Res, UnauthorizedException, UseGuards } from '@nestjs/common';
import { AuthService } from './auth.service';
import { Public } from './decorator/public.decorator';
import { LoginDto, SignupDto } from './dto/auth.dto';
import type { Request, Response } from 'express';
import * as session from 'src/types/session';
import { MfaService } from 'src/mfa/mfa.service';
import { GoogleAuthGuard } from './guard/google-auth.guard';
import { PendingTokenGuard } from './guard/pending-token.guard';
import { DeviceService } from 'src/device/device.service';


@Controller('auth')
export class AuthController {
    constructor(
        private readonly authService: AuthService,
        private readonly mfaService: MfaService,
        private readonly deviceService: DeviceService,
    ) { }

    @Public()
    @Post('signup')
    async register(
        @Body() signupDto: SignupDto,
        @Res() res: Response,
    ) {
        const { pendingToken } = await this.authService.register(signupDto);

        res.cookie('pending_token', pendingToken, {
            httpOnly: true,
            secure: process.env.NODE_ENV === 'production',
            sameSite: process.env.NODE_ENV === 'production' ? 'strict' : 'lax',
            maxAge: 3 * 60 * 1000,
        });
        return res.redirect('/auth/mfa/setup');
    }

    @Public()
    @Post('login')
    async login(
        @Req() req: session.RequestWithUser,
        @Body() loginDto: LoginDto,
        @Res() res: Response,
    ) {
        const ip = req.ip;
        const deviceId = req.headers['user-agent'];

        if (!ip || !deviceId) {
            throw new BadRequestException(`Cannot find IP or deviceId or user data in request object`);
        }

        const result = await this.authService.login(loginDto, deviceId, ip);

        if (!result.isDeviceVerified) {
            res.cookie('pending_token', result.pendingToken, {
                httpOnly: true,
                secure: process.env.NODE_ENV === 'production',
                sameSite: process.env.NODE_ENV === 'production' ? 'strict' : 'lax',
                maxAge: 3 * 60 * 1000,
            });

            // return res.status(200).json({
            //     message: 'MFA verification required',
            //     mfaUrl: '/auth/mfa/verify',
            //     pendingToken: result.pendingToken,
            // });
            return res.redirect('/auth/mfa/setup');
        }

        if (result.mfaRequired) {
            res.cookie('pending_token', result.pendingToken, {
                httpOnly: true,
                secure: process.env.NODE_ENV === 'production',
                sameSite: process.env.NODE_ENV === 'production' ? 'strict' : 'lax',
                maxAge: 3 * 60 * 1000,
            });

            return res.redirect('/auth/mfa/setup');
        }

        // No MFA required → set tokens directly
        res.cookie('access_token', result.accessToken, {
            httpOnly: true,
            secure: process.env.NODE_ENV === 'production',
            sameSite: 'lax',
            maxAge: 30 * 60 * 1000,
        });

        res.cookie('refresh_token', result.refreshToken, {
            httpOnly: true,
            secure: process.env.NODE_ENV === 'production',
            sameSite: 'lax',
            maxAge: 30 * 24 * 60 * 60 * 1000,
        });

        return res.redirect('/users/profile');
        // return res.redirect('/auth/refresh'); call API in frontend in real use case since cannot redirect in server due to different HTTP method
    }

    @Post('refresh')
    async refresh(
        @Req() req: Request,
        @Res({ passthrough: true }) res: Response,
    ) {
        const refreshToken = req.cookies['refresh_token'] || req.body.refreshToken;
        const { newUserPayload: user, accessToken, refreshToken: newRefreshToken } = await this.authService.refresh(refreshToken);

        res.cookie('access_token', accessToken, {
            httpOnly: true,
            secure: false,
            sameSite: 'lax',
            expires: new Date(Date.now() + 30 * 60 * 1000),
        });

        res.cookie('refresh_token', newRefreshToken, {
            httpOnly: true,
            secure: false,
            sameSite: 'lax',
            expires: new Date(Date.now() + 30 * 24 * 60 * 60 * 1000),
        });

        return { accessToken, user };
    }

    @Public()
    @Get('google/callback')
    @UseGuards(GoogleAuthGuard)
    async googleAuthRedirect(@Req() req: session.RequestWithUser, @Res() res: Response) {
        const ip = req.ip;
        const deviceId: string = req.headers['user-agent'] || 'unknown';
        const userId = req.user?.userId;
        const deviceHash = await this.deviceService.hashDeviceId(deviceId);

        if (!userId || !deviceHash || !ip) {
            throw new NotFoundException('Missing required device info or userId or ipAddress');
        }

        const result = await this.authService.googleLogin(req, deviceHash, ip);

        console.log('Is verified? ', result.isDeviceVerified);
        console.log('Is MFA required? ', result.mfaRequired);

        if (!result.isDeviceVerified) {
            res.cookie('pending_token', result.pendingToken, {
                httpOnly: true,
                secure: process.env.NODE_ENV === 'production',
                sameSite: process.env.NODE_ENV === 'production' ? 'strict' : 'lax',
                maxAge: 3 * 60 * 1000,
            });

            // return res.status(200).json({
            //     message: 'MFA verification required',
            //     mfaUrl: '/auth/mfa/verify',
            //     pendingToken: result.pendingToken,
            // });
            return res.redirect('/auth/mfa/setup');
        }

        if (result.mfaRequired) {
            res.cookie('pending_token', result.pendingToken, {
                httpOnly: true,
                secure: process.env.NODE_ENV === 'production',
                sameSite: process.env.NODE_ENV === 'production' ? 'strict' : 'lax',
                maxAge: 3 * 60 * 1000,
            });

            return res.redirect('/auth/mfa/setup');
        }

        res.cookie('access_token', result.accessToken, {
            httpOnly: true,
            secure: process.env.NODE_ENV === 'production',
            sameSite: 'lax',
            maxAge: 30 * 60 * 1000,
        });

        res.cookie('refresh_token', result.refreshToken, {
            httpOnly: true,
            secure: process.env.NODE_ENV === 'production',
            sameSite: 'lax',
            maxAge: 30 * 24 * 60 * 60 * 1000,
        });

        await this.deviceService.registerDevice(result.userId, ip, deviceId);
        return res.redirect('/users/profile');
    }

    @Public()
    @Get('mfa/setup')
    @UseGuards(PendingTokenGuard)
    async setupMfa(@Req() req: session.RequestWithUser) {
        const pendingToken = req.cookies?.pending_token;
        if (!pendingToken) throw new NotFoundException('No pending token for MFA');

        const { sub: userId } = await this.mfaService.verifyPendingToken(pendingToken);
        if (!userId) throw new NotFoundException('Invalid or expiring pending token');

        const { base32, otpauthUrl, qrCodeUrl } = await this.mfaService.generateMfaSecret(userId);
        return { base32, otpauthUrl, qrCodeUrl, pendingToken };
    }

    @Public()
    @Post('mfa/verify')
    @UseGuards(PendingTokenGuard)
    async verifyMfa(
        @Req() req: session.RequestWithUser,
        @Body('totp') totp: string,
        @Res() res: Response
    ) {
        const ip = req.ip;
        const deviceId = req.headers['user-agent'];

        if (!deviceId || !ip) throw new NotFoundException('deviceId or user IP not found');

        const userId = req.user?.sub;
        console.log('Device ID for MFA verify: ', deviceId);
        console.log('userId: ', userId);
        if (!userId || !totp) throw new NotFoundException('userId or Totp for MFA not found');

        try {
            const { accessToken, refreshToken } = await this.mfaService.validateTotp(userId, totp);

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

            await this.deviceService.registerDevice(userId, ip, deviceId);

            res.clearCookie('pending_token');
            return res.redirect('/users/profile');
        } catch (error) {
            console.error('Failed to verify TOTP: ', error);
            throw new UnauthorizedException('Invalid TOTP code');
        }
    }

    @Post('logout')
    async logout(@Req() req: session.RequestWithUser, @Res({ passthrough: true }) res: Response) {
        const jti = req.user?.jti;

        if (!jti) {
            throw new UnauthorizedException('JTI is missing from token');
        }

        await this.authService.logout(jti);

        res.clearCookie('access_token', {
            httpOnly: true,
            sameSite: 'lax',
            secure: false,
        });

        res.clearCookie('refresh_token', {
            httpOnly: true,
            sameSite: 'lax',
            secure: false,
        });

        return { message: `Successfully logout` };
    }
}
