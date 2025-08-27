import { BadRequestException, ForbiddenException, Injectable, Logger, NotFoundException, UnauthorizedException } from '@nestjs/common';
import { User, AuthProvider, DeviceStatus, SessionStatus, Session, Role } from '@prisma/client';
import { userService } from 'src/users/users.service';
import * as bcrypt from 'bcrypt';
import { LoginDto, SignupDto, UserJwtPayload } from './dto/auth.dto';
import { JwtService } from '@nestjs/jwt';
import { SessionService } from 'src/session/session.service';
import { OauthService } from 'src/oauth/oauth.service';
import { MfaService } from 'src/mfa/mfa.service';
import { MfaRequirementStatus } from 'src/types/session';
import { UserDeviceService } from 'src/userDevice/userDevice.service';
import { DeviceService } from 'src/device/device.service';

@Injectable()
export class AuthService {
    constructor(
        private readonly userService: userService,
        private readonly jwtService: JwtService,
        private readonly sessionService: SessionService,
        private readonly oauthService: OauthService,
        private readonly mfaService: MfaService,
        private readonly userDeviceService: UserDeviceService,
        private readonly deviceService: DeviceService,
    ) { }

    private readonly logger = new Logger('AuthService');

    async validateUser(email: string, password: string, deviceId: string): Promise<Omit<User, 'password'> & { mfaRequiredStatus: MfaRequirementStatus }> {
        const DUMMY_HASH = '$2b$10$CwTycUXWue0Thq9StjUM0uJ8e3zoH8JPB8OPm0.9l4qwEYAsfP0r6';
        const user = await this.userService.findUserByEmail(email);

        const passwordIsValid = user?.password
            ? await bcrypt.compare(password, user.password)
            : await bcrypt.compare(password, DUMMY_HASH);

        if (!passwordIsValid || !user) throw new UnauthorizedException('Password is incorrect');

        const mfaStatus = await this.checkMfaRequirement(user.userId, deviceId);
        const { password: _, ...result } = user;

        return {
            mfaRequiredStatus: mfaStatus,
            ...result,
        };
    }

    async generateToken(session: Session, user: { userId: string; email: string; role: Role }) {
        const payload: UserJwtPayload = {
            sub: user.userId,
            email: user.email,
            role: user.role,
            jti: session.jti,
            deviceId: session.deviceId,
            sessionId: session.sessionId,
        };
    
        const accessToken = await this.jwtService.signAsync(payload, { expiresIn: '30m' });
        const refreshToken = await this.jwtService.signAsync(payload, { expiresIn: '30d' });
    
        // Update session refresh token hash in DB
        const newExpiry = new Date(Date.now() + 30 * 24 * 60 * 60 * 1000);
        const newHashedToken = await bcrypt.hash(refreshToken, 10);
        await this.sessionService.refreshSession(newHashedToken, newExpiry, session.deviceId, session.userId);
    
        return { accessToken, refreshToken };
    }

    async checkMfaRequirement(userId: string, deviceId: string): Promise<MfaRequirementStatus> {
        const device = await this.userDeviceService.findUserDevice(userId, deviceId);
        if (!device) return MfaRequirementStatus.required;

        if (userId && device.userId !== userId) return MfaRequirementStatus.required;

        if (!device?.mfaTrustExpiresAt ||
            !device.mfaLastVerifiedAt ||
            device.deviceStatus !== DeviceStatus.Trusted) {
            return MfaRequirementStatus.required;
        }

        if (device.mfaTrustExpiresAt < new Date()) return MfaRequirementStatus.expired;

        const mfaTrusted = device.isMfaTrusted &&
            device?.mfaTrustExpiresAt > new Date() &&
            device.mfaLastVerifiedAt;

        if (mfaTrusted) return MfaRequirementStatus.skip

        return MfaRequirementStatus.required;
    }

    async login(loginDto: LoginDto, deviceId: string, ipAddress: string, userAgent: string) {
        if (!loginDto.email || !loginDto.password) throw new BadRequestException('Email and password are required');

        const { userId, mfaRequiredStatus } = await this.validateUser(loginDto.email, loginDto.password, deviceId);
        await this.deviceService.getOrCreateDevice(ipAddress, userAgent, deviceId);

        const userDevice = await this.userDeviceService.getOrCreateUserDevice(userId, deviceId);
        const isDeviceVerified = await this.userDeviceService.isUserDeviceVerified(userId, deviceId);

        if (mfaRequiredStatus !== MfaRequirementStatus.skip || !isDeviceVerified) {
            const pendingToken = await this.mfaService.generatePendingToken(userId);
            return { pendingToken, mfaRequired: true, userId, isDeviceVerified };
        }

        const { accessToken, refreshToken } = await this.mfaService.generateFinalToken(userId, true, ipAddress, userAgent, deviceId, userDevice.userDeviceId);
        return { accessToken, refreshToken, mfaRequired: false, userId, isDeviceVerified };
    }

    async register(signupDto: SignupDto, deviceId: string, ipAddress: string, userAgent: string) {
        if (!signupDto.email || !signupDto.password) throw new BadRequestException('Email and password are required');

        const user = await this.userService.createUser(signupDto, AuthProvider.Local);

        let device = await this.deviceService.findDeviceById(deviceId);
        if (!device) await this.deviceService.getOrCreateDevice(ipAddress, userAgent, deviceId);
        const userDevice = await this.userDeviceService.getOrCreateUserDevice(user.userId, deviceId);

        const pendingToken = await this.mfaService.generatePendingToken(user.userId);
        return { pendingToken, mfaRequired: true };
    }

    async refresh(refreshToken: string, deviceId: string, userId: string) {
        const payload = await this.jwtService.verifyAsync(refreshToken);

        // Find and verify session
        const session = await this.sessionService.findActiveSessionByJti(payload.jti);
        if (!session) throw new NotFoundException('Existing sesssion to refresh not found');
        await this.sessionService.verifySession(session?.userDeviceId, session?.userId);

        const user = await this.userService.findUserByUserId(userId);
        const { accessToken, refreshToken: newRefreshToken } = await this.generateToken(session, user);

        // Update session (rotation)
        const newExpiry = new Date(Date.now() + 30 * 24 * 60 * 60 * 1000);
        const newHashedToken = await bcrypt.hash(newRefreshToken, 10);
        await this.sessionService.refreshSession(newHashedToken, newExpiry, deviceId, userId);

        return { accessToken, refreshToken: newRefreshToken };
    }

    async googleLogin(req, deviceId: string, ipAddress: string, userAgent: string): Promise<any> {
        if (!req.user) throw new NotFoundException('No user info received for Google login');

        const googleId = req.user.googleId || req.user.providerUserId;
        const email = req.user.emails?.[0]?.value || req.user.user.email;

        let oauthAccount = await this.oauthService.findOauthAccount(AuthProvider.Google, googleId);
        let user = oauthAccount?.user;

        if (!user) {
            // If no linked OAuth account, check if user exists by email
            user = await this.userService.findUserByEmail(email);
            if (user && user.provider !== AuthProvider.Google)
                throw new ForbiddenException(`Account with this email exists via ${user.provider}, please log in with that method.`)

            user ??= await this.userService.createUser({ email }, AuthProvider.Google, googleId);
        }

        await this.deviceService.getOrCreateDevice(ipAddress, userAgent, deviceId);

        const userDevice = await this.userDeviceService.getOrCreateUserDevice(user.userId, deviceId);
        const isDeviceVerified = await this.userDeviceService.isUserDeviceVerified(user.userId, deviceId);

        const mfaRequired = (await this.checkMfaRequirement(user.userId, deviceId));
        if (mfaRequired === MfaRequirementStatus.expired) throw new UnauthorizedException('Session expired, please login again');

        if ((mfaRequired !== MfaRequirementStatus.skip) || !isDeviceVerified) {
            const pendingToken = await this.mfaService.generatePendingToken(user.userId);
            return { mfaRequired, isDeviceVerified, pendingToken, userId: user.userId };
        }

        const existingSession = await this.sessionService.findActiveSessionByUserDevice(user.userId, deviceId);
        const { accessToken, refreshToken } = await this.mfaService.generateFinalToken(user.userId, true, ipAddress, userAgent, deviceId, userDevice.userDeviceId, existingSession?.jti );

        return { accessToken, refreshToken, mfaRequired: false, isDeviceVerified: true, userId: user.userId };
    }

    // Revoke by device instead to change from global logout to device logout
    async logout(userId: string, deviceId: string, reason: string = "Example reason") {
        if (!deviceId) throw new NotFoundException('Device ID for logout not found');

        const userDevice = await this.userDeviceService.findUserDevice(userId, deviceId);
        if (!userDevice || userDevice.userId !== userId) 
            throw new ForbiddenException('Invalid or unauthorized device logout attempt');

        const revokeCount = await this.sessionService.revokeSessionByDevice(deviceId);
        if (revokeCount === 0) throw new NotFoundException(`No active session found for device ${deviceId}`)

        await this.userDeviceService.revokedUserDevice(userDevice.userDeviceId, reason);
        return { success: true, revokedSessions: revokeCount };
    }

    async logoutFromAllDevices(userId: string, reason: string = "Example reason") {
        const revokeUserDeviceCount = await this.userDeviceService.revokedAllUserDevices(userId, reason);
        const revokeSessionCount = await this.sessionService.revokeAllUserSessions(userId, reason);

        return {
            message: `Revoke ${revokeSessionCount} session(s) and ${revokeUserDeviceCount} device(s) successfully`,
            success: true,
        };
    }
}