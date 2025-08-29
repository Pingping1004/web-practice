import { BadRequestException, Body, Controller, Get, NotFoundException, Post, Req, Res, UnauthorizedException, UseGuards } from '@nestjs/common';
import { AuthService } from './auth.service';
import { Public } from './decorator/public.decorator';
import { LoginDto, SignupDto, UserJwtPayload } from './dto/auth.dto';
import type { CookieOptions, Request, Response } from 'express';
import * as session from 'src/types/session';
import { GoogleAuthGuard } from './guard/google-auth.guard';
import { v4 as uuidv4 } from 'uuid';
import { UserService } from 'src/users/users.service';


@Controller('auth')
export class AuthController {
    constructor(
        private readonly authService: AuthService,
        private readonly userService: UserService,
    ) { }

    @Public()
    @Post('signup')
    async register(
        @Req() req: session.RequestWithUser,
        @Body() signupDto: SignupDto,
        @Res() res: Response,
    ) {
        const ip = req.ip;
        const userAgent = req.headers['user-agent'];

        let deviceId = req.cookies['deviceId'];
        if (!deviceId) {
            deviceId = uuidv4();

            res.cookie('deviceId', deviceId, {
                httpOnly: true,
                sameSite: process.env.NODE_ENV === 'production' ? 'strict' : 'lax',
                secure: process.env.NODE_ENV === 'production',
                maxAge: 1000 * 60 * 60 * 24 * 365, // 1 year
                path: '/',
            });
        }

        if (!ip || !userAgent) throw new BadRequestException(`Cannot find IP or user agent in request object`);

        const { pendingToken } = await this.authService.register(signupDto, deviceId, ip, userAgent);

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
        const userAgent = req.headers['user-agent'];

        let deviceId = req.cookies['deviceId'];
        console.log('deviceId in login controller: ', deviceId);

        if (!deviceId) {
            deviceId = uuidv4();
            console.log('Newly generate deviceId');

            res.cookie('deviceId', deviceId, {
                httpOnly: true,
                sameSite: process.env.NODE_ENV === 'production' ? 'strict' : 'lax',
                secure: process.env.NODE_ENV === 'production',
                maxAge: 1000 * 60 * 60 * 24 * 365, // 1 year
                path: '/',
            });
        }

        if (!ip || !userAgent) {
            throw new BadRequestException(`Cannot find IP or user agent in request object`);
        }

        const result = await this.authService.login(loginDto, deviceId, ip, userAgent);
        console.log('Login result: ', result);

        if (!result.isDeviceVerified) {
            res.cookie('pending_token', result.pendingToken, {
                httpOnly: true,
                secure: process.env.NODE_ENV === 'production',
                sameSite: process.env.NODE_ENV === 'production' ? 'strict' : 'lax',
                maxAge: 3 * 60 * 1000,
            });

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
        @Req() req: session.RequestWithUser,
        @Res({ passthrough: true }) res: Response,
    ) {
        const deviceId = req.cookies['deviceId'];
        const userId = req.user?.sub;
        const refreshToken = req.cookies['refresh_token'] || req.body.refreshToken;

        if (!deviceId || !userId) throw new NotFoundException('deviceId or userId not found');

        const { accessToken, refreshToken: newRefreshToken } = await this.authService.refresh(refreshToken, deviceId, userId);

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

        const user = await this.userService.findUserByUserId(userId);
        return { accessToken, user };
    }

    @Public()
    @Get('google')
    @UseGuards(GoogleAuthGuard)
    async googleLogin() {
        // Handle google login via passport-strategy
    }

    @Public()
    @Get('google/callback')
    @UseGuards(GoogleAuthGuard)
    async googleAuthRedirect(@Req() req: session.RequestWithUser, @Res() res: Response) {
        const ip = req.ip;
        const userAgent = req.headers['user-agent'];

        let deviceId = req.cookies['deviceId'];
        if (!deviceId) {
            deviceId = uuidv4();

            res.cookie('deviceId', deviceId, {
                httpOnly: true,
                sameSite: process.env.NODE_ENV === 'production' ? 'strict' : 'lax',
                secure: process.env.NODE_ENV === 'production',
                maxAge: 1000 * 60 * 60 * 24 * 365, // 1 year
                path: '/',
            });
        }

        if (!ip || !userAgent) {
            throw new NotFoundException('Missing required device info or userId or user agent or ipAddress');
        }

        const result = await this.authService.googleLogin(req, deviceId, ip, userAgent);

        if (!result.isDeviceVerified) {
            res.cookie('pending_token', result.pendingToken, {
                httpOnly: true,
                secure: process.env.NODE_ENV === 'production',
                sameSite: process.env.NODE_ENV === 'production' ? 'strict' : 'lax',
                maxAge: 3 * 60 * 1000,
            });

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

        return res.redirect('/users/profile');
    }

    @Post('logout')
    async logout(@Req() req: Request, @Res({ passthrough: true }) res: Response) {
        const deviceId = req.cookies['deviceId'];
        const { sub: userId } = (req.user as UserJwtPayload);

        if (!userId || !deviceId) throw new UnauthorizedException('userId or deviceId is missing from token');

        await this.authService.logout(userId, deviceId);

        // Clear all auth-related cookies (consistent options)
        const cookieOptions: CookieOptions = {
            httpOnly: true,
            sameSite: process.env.NODE_ENV === 'production' ? 'strict' : 'lax',
            secure: process.env.NODE_ENV === 'production',
            path: '/', // ensure all paths are cleared
        };

        res.clearCookie('access_token', cookieOptions);
        res.clearCookie('refresh_token', cookieOptions);

        return { message: `Successfully logout` };
    }
}
