import { BadRequestException, ForbiddenException, Injectable, Logger, NotFoundException, UnauthorizedException } from '@nestjs/common';
import { User, AuthProvider, DeviceStatus } from '@prisma/client';
import { UsersService } from 'src/users/users.service';
import * as bcrypt from 'bcrypt';
import { LoginDto, SignupDto, UserJwtPayload, UserPayloadDto } from './dto/auth.dto';
import { JwtService } from '@nestjs/jwt';
import { v4 as uuidv4 } from 'uuid';
import { SessionService } from 'src/session/session.service';
import { OauthService } from 'src/oauth/oauth.service';
import { MfaService } from 'src/mfa/mfa.service';
import { DeviceService } from 'src/device/device.service';
import { MfaRequirementStatus } from 'src/types/session';

@Injectable()
export class AuthService {
    constructor(
        private readonly usersService: UsersService,
        private readonly jwtService: JwtService,
        private readonly sessionService: SessionService,
        private readonly oauthService: OauthService,
        private readonly mfaService: MfaService,
        private readonly deviceService: DeviceService,
    ) { }

    private readonly logger = new Logger('AuthService');

    async validateUser(email: string, password: string): Promise<Omit<User, 'password'> & { isMfaRequired?: boolean }> {
        const DUMMY_HASH = '$2b$10$CwTycUXWue0Thq9StjUM0uJ8e3zoH8JPB8OPm0.9l4qwEYAsfP0r6';
        const user = await this.usersService.findUserByEmail(email);
        let passwordIsValid: boolean = false;

        if (user?.password) {
            passwordIsValid = await bcrypt.compare(password, user.password);
        } else {
            await bcrypt.compare(password, DUMMY_HASH);
            this.logger.warn('Login attempt for non-existent user: ', email);
        }

        if (!passwordIsValid || !user) throw new UnauthorizedException('Password is incorrect');

        const { password: _, ...result } = user;
        return result;
    }

    async generateToken(payload: UserJwtPayload, existingJti?: string) {
        console.log('Original JTI: ', existingJti);
        const jti = existingJti || uuidv4();
        console.log('JTI in generateToken: ', jti);

        const accessToken = await this.jwtService.signAsync({
            ...payload,
            jti,
        }, { expiresIn: '30m' });

        const refreshToken = await this.jwtService.signAsync({
            ...payload,
            jti,
        }, { expiresIn: '30d' });

        return { accessToken, refreshToken, jti };
    }

    async checkMfaRequirement(userId: string, deviceId: string) {
        const device = await this.deviceService.findDeviceById(deviceId);
        if (!device) return { mfaRequired: MfaRequirementStatus.required };

        if (userId && device.userId !== userId) {
            return { mfaRequired: MfaRequirementStatus.required };
        }

        if (!device?.mfaTrustExpiresAt || 
            !device.mfaLastVerifiedAt || 
            device.deviceStatus !== DeviceStatus.Trusted) {
            return { mfaRequired: MfaRequirementStatus.required };
        }
        if (device.mfaTrustExpiresAt < new Date()) return { mfaRequired: MfaRequirementStatus.expired };

        const mfaTrusted = device.isMfaTrusted && 
        device?.mfaTrustExpiresAt > new Date() &&
        device.mfaLastVerifiedAt;

        if (mfaTrusted) return { mfaRequired: MfaRequirementStatus.skip }

        return {
            mfaRequired: MfaRequirementStatus.required,
        }
    }

    async login(loginDto: LoginDto, deviceId: string, ipAddress: string, userAgent: string) {
        if (!loginDto.email || !loginDto.password) {
            throw new BadRequestException('Email and password are required');
        }

        const { userId, mfaEnabled } = await this.validateUser(loginDto.email, loginDto.password);
        const isDeviceVerified = await this.deviceService.verifyDevice(deviceId);

        if (mfaEnabled) {
            const { mfaRequired } = await this.checkMfaRequirement(userId, deviceId);
            if (mfaRequired !== MfaRequirementStatus.skip || !isDeviceVerified) {
                const pendingToken = await this.mfaService.generatePendingToken(userId);
                return { pendingToken, mfaRequired: true, userId, isDeviceVerified };
            }
        }

        const existingSession = await this.sessionService.findActiveSessionByDevice(userId, deviceId);

        let sessionJti: string;
        if (existingSession) {
            sessionJti = existingSession.jti;
        } else {
            sessionJti = uuidv4();
            console.log('Session JTI is newly created');
        }

        if (existingSession) {
            await this.sessionService.verifySession(existingSession.jti, deviceId, userId);
        }

        await this.deviceService.setRevokeDevice(deviceId, false);
        const { accessToken, refreshToken } = await this.mfaService.generateFinalToken(userId, true, ipAddress, userAgent, deviceId, sessionJti);
        return { accessToken, refreshToken, mfaRequired: false, userId, isDeviceVerified };
    }

    async register(signupDto: SignupDto) {
        const user = await this.usersService.createUser(signupDto, AuthProvider.Local);

        const pendingToken = await this.mfaService.generatePendingToken(user.userId);
        return { pendingToken, mfaRequired: true };
    }

    async refresh(refreshToken: string, deviceId: string, userId: string) {
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
        const newUserPayload: UserJwtPayload = {
            sub: payload.sub,
            email: payload.email,
            role: payload.role,
            jti: payload.jti,
            userId: payload.userId,
            deviceId: storedSession.deviceId,
        };

        const { accessToken, refreshToken: newRefreshToken } = await this.generateToken(newUserPayload, payload.jti);

        const newExpiry = new Date(Date.now() + 30 * 24 * 60 * 60 * 1000);
        const newHashedToken = await bcrypt.hash(newRefreshToken, 10);

        // 5️⃣ Update session (rotation)
        await this.sessionService.refreshSession(newHashedToken, newExpiry, deviceId, userId);

        // 5️⃣ Return new tokens
        return {
            accessToken,
            refreshToken: newRefreshToken,
            newUserPayload,
        };
    }

    async googleLogin(req, deviceId: string, ipAddress: string, userAgent: string): Promise<any> {
        if (!req.user) throw new NotFoundException('No user info received for Google login');

        const googleId = req.user.googleId || req.user.providerUserId;
        const email = req.user.emails?.[0]?.value || req.user.user.email;

        let oauthAccount = await this.oauthService.findOauthAccount(AuthProvider.Google, googleId);
        let user = oauthAccount?.user;

        if (!user) {
            // If no linked OAuth account, check if user exists by email
            user = await this.usersService.findUserByEmail(email);

            if (user && user.provider !== AuthProvider.Google) {
                throw new ForbiddenException(`Account with this email exists via ${user.provider}, please log in with that method.`)
            }

            user ??= await this.usersService.createUser({
                email,
            }, AuthProvider.Google, googleId);
        }

        const isDeviceVerified = await this.deviceService.verifyDevice(deviceId);
        const mfaRequired = (await this.checkMfaRequirement(user.userId, deviceId)).mfaRequired;

        if (mfaRequired === MfaRequirementStatus.expired) {
            throw new UnauthorizedException('Session expired, please login again');
        }

        if ((mfaRequired !== MfaRequirementStatus.skip) || !isDeviceVerified) {
            const pendingToken = await this.mfaService.generatePendingToken(user.userId);
            return { mfaRequired, isDeviceVerified, pendingToken, userId: user.userId };
        }

        const activeSession = await this.sessionService.findActiveSessionByDevice(user.userId, deviceId);
        if (activeSession) await this.sessionService.verifySession(activeSession.jti, deviceId, user.userId);

        const existingSession = await this.sessionService.findActiveSessionByDevice(user.userId, deviceId);

        let sessionJti: string;
        if (existingSession) {
            sessionJti = existingSession.jti;
        } else {
            sessionJti = uuidv4();
        }

        const { accessToken, refreshToken } = await this.mfaService.generateFinalToken(user.userId, true, ipAddress, userAgent, deviceId, sessionJti);
        return { accessToken, refreshToken, mfaRequired: false, isDeviceVerified: true, userId: user.userId };
    };

    // Revoke by device instead to change from global logout to device logout
    async logout(userId: string, deviceId: string) {
        if (!deviceId) throw new NotFoundException('Device ID for logout not found');

        const device = await this.deviceService.findDeviceById(deviceId);
        console.log('userId: ', userId);
        console.log('device.userId: ', device?.userId);
        if (!device || device.userId !== userId) {
            throw new ForbiddenException('Invalid or unauthorized device logout attempt');
        }

        const revokeCount = await this.sessionService.revokeSessionByDevice(deviceId);
        await this.deviceService.setRevokeDevice(deviceId, true);
        if (revokeCount === 0) {
            throw new NotFoundException(`No active session found for device ${deviceId}`)
        }

        return { success: true, revokedSessions: revokeCount };
    }

    async logoutFromAllDevices(jti: string) {
        await this.sessionService.revokedSessionByJti(jti);
    }
}