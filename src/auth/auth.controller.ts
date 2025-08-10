import { Body, Controller, Post, Req, Res, UnauthorizedException } from '@nestjs/common';
import { AuthService } from './auth.service';
import { Public } from './decorator/public.decorator';
import { LoginDto, SignupDto } from './dto/auth.dto';
import type { Request, Response } from 'express';
import * as session from 'src/types/session';

@Controller('auth')
export class AuthController {
    constructor(
        private readonly authService: AuthService,
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
            maxAge: 7 * 24 * 60 * 60 * 1000,
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
            maxAge: 7 * 24 * 60 * 60 * 1000,
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
            expires: new Date(Date.now() + 7 * 24 * 60 * 60 * 1000),
        });

        return { accessToken, user };
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
            sameSite:'lax',
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
