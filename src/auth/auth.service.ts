import { BadRequestException, ForbiddenException, Injectable, Logger, NotFoundException, UnauthorizedException } from '@nestjs/common';
import { User, AuthProvider } from '@prisma/client';
import { UsersService } from 'src/users/users.service';
import * as bcrypt from 'bcrypt';
import { LoginDto, SignupDto, UserPayloadDto } from './dto/auth.dto';
import { JwtService } from '@nestjs/jwt';
import { v4 as uuidv4 } from 'uuid';
import { SessionService } from 'src/session/session.service';
import { OauthService } from 'src/oauth/oauth.service';
import { MfaService } from 'src/mfa/mfa.service';

@Injectable()
export class AuthService {
    constructor(
        private readonly usersService: UsersService,
        private readonly jwtService: JwtService,
        private readonly sessionService: SessionService,
        private readonly oauthService: OauthService,
        private readonly mfaService: MfaService,
    ) { }

    private readonly logger = new Logger('AuthService');

    async validateUser(username: string, password: string): Promise<Omit<User, 'password'> & { isMfaRequired?: boolean }> {
        const DUMMY_HASH = '$2b$10$CwTycUXWue0Thq9StjUM0uJ8e3zoH8JPB8OPm0.9l4qwEYAsfP0r6';
        const user = await this.usersService.findUserByUserName(username);
        let passwordIsValid: boolean = false;

        if (user?.password) {
            passwordIsValid = await bcrypt.compare(password, user.password);
        } else {
            await bcrypt.compare(password, DUMMY_HASH);
            this.logger.warn('Login attempt for non-existent user: ', username);
        }

        if (!passwordIsValid || !user) throw new UnauthorizedException('Password is incorrect');

        const { password: _, ...result } = user;
        return result;
    }

    async generateToken(payload: UserPayloadDto) {
        const jti = uuidv4();

        const accessToken = await this.jwtService.signAsync({
            ...payload,
            jti,
        }, { expiresIn: '30m' });

        const refreshToken = await this.jwtService.signAsync({
            ...payload,
            jti,
        }, { expiresIn: '30d' });

        return { accessToken, refreshToken };
    }

    async checkMfaRequirement(userId: string): Promise<boolean> {
        const session = await this.sessionService.findActiveSessionByUserId(userId);
        if (session && session.mfaVerified && !this.mfaService.isExpired(session)) {
            return false; // skip MFA for active session
        }
        return true; // MFA required
    }

    async login(loginDto: LoginDto) {
        if (!loginDto.username) throw new NotFoundException('Username not found in login DTO');
        if (!loginDto.password) throw new NotFoundException('Password not found in login DTO');

        const user = await this.validateUser(loginDto.username, loginDto.password);

        if (user.mfaEnabled) {
            const mfaRequired = await this.checkMfaRequirement(user.userId);
            if (mfaRequired) {
                // Check if MFA requirement can be skipped (active session not expired)
                const pendingToken = await this.mfaService.generatePendingToken(user.userId);
                return { pendingToken, mfaRequired: true };
            }
        }

        const { accessToken, refreshToken } = await this.mfaService.generateFinalToken(user.userId, true);
        return { accessToken, refreshToken, mfaRequired: false };
    }

    async register(signupDto: SignupDto) {
        const user = await this.usersService.createuser(signupDto, AuthProvider.Local);

        const pendingToken = await this.mfaService.generatePendingToken(user.userId);
        return { pendingToken, mfaRequired: true };
    }

    async refresh(refreshToken: string) {
        // 1️⃣ Verify the refresh token
        const payload = await this.jwtService.verifyAsync(refreshToken);

        // 2️⃣ Find the session
        const storedSession = await this.sessionService.findSessionByJti(payload.jti);
        if (!storedSession || storedSession.isRevoked) {
            throw new UnauthorizedException('Invalid or revoked refresh token');
        }

        // 3️⃣ Check expiry
        if (storedSession.expiresAt < new Date()) {
            throw new UnauthorizedException('Refresh token expired');
        }

        // 4️⃣ Generate a new refresh token & hash it
        const jti = uuidv4();
        const newUserPayload: UserPayloadDto = {
            sub: payload.sub,
            email: payload.email,
            role: payload.role,
            jti,
        };

        const { accessToken, refreshToken: newRefreshToken } = await this.generateToken(newUserPayload,);

        const newExpiry = new Date(Date.now() + 30 * 24 * 60 * 60 * 1000);
        const newHashedToken = await bcrypt.hash(newRefreshToken, 10);

        // 5️⃣ Update session (rotation)
        await this.sessionService.refreshSession(payload.jti, newHashedToken, newExpiry);

        // 5️⃣ Return new tokens
        return {
            accessToken,
            refreshToken: newRefreshToken,
            newUserPayload,
        };
    }

    async googleLogin(req): Promise<any> {
        if (!req.user) throw new NotFoundException('No user info received for Google login');

        console.log('Req user for google login service: ', req.user)
        const googleId = req.user.googleId || req.user.providerUserId;
        const email = req.user.emails?.[0]?.value || req.user.user.email;
        const username = req.user.username || email?.split('@')[0];

        if (!email) {
            throw new BadRequestException('Email is required from Google OAuth');
        }

        let oauthAccount = await this.oauthService.findOauthAccount(AuthProvider.Google, googleId);

        let user = oauthAccount?.user;
        if (!user) {
            // If no linked OAuth account, check if user exists by email
            user = await this.usersService.findUserByEmail(email);

            if (user) {
                if (user.provider !== AuthProvider.Google) {
                    throw new ForbiddenException(`Account with this email exists via ${user.provider}, please log in with that method.`)
                }
            } else {
                user = await this.usersService.createuser(
                    {
                        email,
                        username,
                    },
                    AuthProvider.Google,
                    googleId,
                );
            }
        }

        const pendingToken = await this.mfaService.generatePendingToken(user.userId);
        return { pendingToken, mfaRequired: true };
    };

    async logout(jti: string) {
        await this.sessionService.revokedSessionByJti(jti);
    }
}