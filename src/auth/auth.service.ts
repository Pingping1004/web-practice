import { ForbiddenException, Injectable, Logger, NotFoundException, UnauthorizedException } from '@nestjs/common';
import { Role, User, AuthProvider } from '@prisma/client';
import { UsersService } from 'src/users/users.service';
import * as bcrypt from 'bcrypt';
import { LoginDto, SignupDto, UserPayloadDto } from './dto/auth.dto';
import { JwtService } from '@nestjs/jwt';
import { v4 as uuidv4 } from 'uuid';
import { SessionService } from 'src/session/session.service';
import { OauthService } from 'src/oauth/oauth.service';

@Injectable()
export class AuthService {
    constructor(
        private readonly usersService: UsersService,
        private readonly jwtService: JwtService,
        private readonly sessionService: SessionService,
        private readonly oauthService: OauthService,
    ) { }

    private readonly logger = new Logger('AuthService');

    async validateUser(username: string, password: string): Promise<Omit<User, 'password'>> {
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

    private async generateToken(payload: UserPayloadDto) {
        const jti = uuidv4();

        const accessToken = await this.jwtService.signAsync({
            ...payload,
            jti,
        }, { expiresIn: '30m' });

        const refreshToken = await this.jwtService.signAsync({
            ...payload,
            jti,
        }, { expiresIn: '7d' });

        const expiresAt = new Date(Date.now() + 7 * 24 * 60 * 60 * 1000);
        const hashingToken = await bcrypt.hash(refreshToken, 10);
        await this.sessionService.createSession({
            jti,
            hashedToken: hashingToken,
            userId: payload.sub,
            expiresAt,
        });

        return { accessToken, refreshToken };
    }

    async login(loginDto: LoginDto) {
        if (!loginDto.username) throw new NotFoundException('Username not found in login DTO');
        if (!loginDto.password) throw new NotFoundException('Password not found in login DTO');

        const user = await this.validateUser(loginDto.username, loginDto.password);

        const jti = uuidv4();
        const userPayload: UserPayloadDto = {
            sub: user.userId,
            email: user.email,
            role: user.role,
            jti,
        };

        const { accessToken, refreshToken } = await this.generateToken(userPayload);

        return {
            userPayload,
            accessToken,
            refreshToken,
        }
    }

    async register(signupDto: SignupDto) {
        const user = await this.usersService.createuser(signupDto, AuthProvider.Local);

        const jti = uuidv4();
        const userPayload: UserPayloadDto = {
            sub: user.userId,
            email: user.email,
            role: user.role,
            jti,
        };

        const { accessToken, refreshToken } = await this.generateToken(userPayload);
        return { user, accessToken, refreshToken };
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

        const { accessToken, refreshToken: newRefreshToken } = await this.generateToken(newUserPayload);

        const newExpiry = new Date(Date.now() + 7 * 24 * 60 * 60 * 1000);
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

        const { emails, username, googleId } = req.user;
        const email = emails?.[0].value ?? null;

        let oauthAccount = await this.oauthService.findOauthAccount(AuthProvider.Google, googleId);

        let user = oauthAccount?.user;
        if (!user) {
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

        const userPayload: UserPayloadDto = {
            sub: user?.userId,
            email: email,
            role: Role.User,
            jti: uuidv4(),
        };

        return await this.generateToken(userPayload);
    };

    async logout(jti: string) {
        await this.sessionService.revokedSessionByJti(jti);
    }
}