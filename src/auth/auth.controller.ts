import { Body, Controller, Get, NotFoundException, Post, Req, Res, UnauthorizedException, UseGuards } from '@nestjs/common';
import { AuthService } from './auth.service';
import { Public } from './decorator/public.decorator';
import { LoginDto, SignupDto } from './dto/auth.dto';
import type { Request, Response } from 'express';
import * as session from 'src/types/session';
import { MfaService } from 'src/mfa/mfa.service';
import { GoogleAuthGuard } from './guard/google-auth.guard';
import { PendingTokenGuard } from './guard/pending-token.guard';
import { UsersService } from 'src/users/users.service';


@Controller('auth')
export class AuthController {
    constructor(
        private readonly authService: AuthService,
        private readonly userService: UsersService,
        private readonly mfaService: MfaService,
    ) { }

    @Public()
    @Post('signup')
    async register(
        @Body() signupDto: SignupDto,
        @Res({ passthrough: true }) res: Response,
    ) {
        const { user, accessToken, refreshToken } = await this.authService.register(signupDto);

        res.cookie('access_token', accessToken, {
            httpOnly: true,
            secure: false,
            sameSite: 'lax',
            maxAge: 30 * 60 * 1000,
        });

        res.cookie('refresh_token', refreshToken, {
            httpOnly: true,
            secure: false,
            sameSite: 'lax',
            maxAge: 30 * 24 * 60 * 60 * 1000,
        });

        return {
            message: 'Successfully signup',
            user,
            accessToken,
            refreshToken,
        };
    }

    @Public()
    @Post('login')
    async login(
        @Body() loginDto: LoginDto,
        @Res({ passthrough: true }) res: Response,
    ) {
        const { userPayload: user, accessToken, refreshToken } = await this.authService.login(loginDto);

        res.cookie('access_token', accessToken, {
            httpOnly: true,
            secure: false,
            sameSite: 'lax',
            maxAge: 30 * 60 * 1000,
        });

        res.cookie('refresh_token', refreshToken, {
            httpOnly: true,
            secure: false,
            sameSite: 'lax',
            maxAge: 30 * 24 * 60 * 60 * 1000,
        });

        return {
            message: 'Successfully login',
            user,
            accessToken,
            refreshToken,
        }
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

    @Get('mfa/check')
    async getProtectedResource(@Req() req) {
        await this.authService.isMfaRequired(req.user.jti);
    }

    @Public()
    @Get('google/callback')
    @UseGuards(GoogleAuthGuard)
    async googleAuthRedirect(@Req() req, @Res() res: Response) {
        const { pendingToken } = await this.authService.googleLogin(req);

        res.cookie('pending_token', pendingToken, {
            httpOnly: true,
            secure: process.env.NODE_ENV === 'production',
            sameSite: process.env.NODE_ENV === 'production' ? 'strict' : 'lax',
            maxAge: 3 * 60 * 1000,
        });

        return res.redirect('/auth/mfa/setup');
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
        const userId = req.user?.sub;
        if (!userId || !totp) throw new NotFoundException('userId or Totp for MFA not found');

        try {
            // await this.mfaService.verifyPendingToken(userId);
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

            res.clearCookie('pending_token');
            return res.redirect('/users/profile');
        } catch (error) {
            console.error('Failed to verify TOTP: ', error.message);
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
