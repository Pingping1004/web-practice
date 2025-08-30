import { forwardRef, Inject, Injectable, NotFoundException, UnauthorizedException } from "@nestjs/common";
import { Session, SessionStatus } from "@prisma/client";
import { PrismaService } from "prisma/prisma.service";
import { LoggingService } from "src/logging/logging.service";
import { MfaService } from "src/mfa/mfa.service";
import { SessionPayload } from "src/types/session";
import { UserDeviceService } from "src/userDevice/userDevice.service";

@Injectable()
export class SessionService {
    constructor(
        private readonly prisma: PrismaService,
        private readonly userDeviceService: UserDeviceService,
        private readonly logger: LoggingService,
        @Inject(forwardRef(() => MfaService)) private readonly mfaService: MfaService,
    ) { }

    async getOrCreateSession(sessionPayload: SessionPayload) {
        const { userId, deviceId, userDeviceId, hashedToken } = sessionPayload;
        let session = await this.findActiveSessionByUserDevice(userId, userDeviceId);

        if (!session) {
            session = await this.prisma.session.create({
                data: sessionPayload,
            });
        } else {
            const newExpiry = new Date(Date.now() + 30 * 24 * 60 * 60 * 1000);
            session = await this.refreshSession(hashedToken, newExpiry, deviceId, userId);
        }

        return session;
    }

    async findActiveSessionByJti(jti: string): Promise<Session | null> {
        const session = await this.prisma.session.findUnique({
            where: { 
                jti,
                status: SessionStatus.Active,
                expiresAt: { gt: new Date() },
            },
        });

        return session;
    }

    async verifySession(userDeviceId: string, userId: string) {
        const session = await this.findActiveSessionByUserDevice(userId, userDeviceId);
        
        if (!session) throw new UnauthorizedException(`Session to verify not found`);
        if (!session.mfaVerified) throw new UnauthorizedException('MFA not completed');

        const mfaVerifiedAt =  session.mfaVerifiedAt ? session.mfaVerifiedAt : session.issuedAt;

        const isSessionExpired = this.mfaService.isSessionExpired({
            issuedAt: session.issuedAt,
            mfaVerifiedAt,
            expiresAt: session.expiresAt,
        });

        this.logger.log(`Is session expired: ${isSessionExpired}`);

        if (session.status !== SessionStatus.Active || isSessionExpired) throw new UnauthorizedException(`Session revoked or expired`);

        if (session.userDeviceId !== userDeviceId) {
            throw new UnauthorizedException('Session does not belong to this device');
        }

        if (userId && session.userId !== userId) {
            throw new UnauthorizedException('Session does not belong to this user');
        }

        const verifiedSession = await this.markSessionAsVerify(userId, userDeviceId, new Date());
        return verifiedSession;
    }

    async markSessionAsVerify(userId: string, deviceId: string, verifyAt: Date) {
        let session = await this.findActiveSessionByUserDevice(userId, deviceId);
        if (!session) throw new UnauthorizedException(`Session to verify not found`);

        if (session.mfaVerified) return session;

        session = await this.prisma.session.update({
            where: { jti: session.jti },
            data: {
                mfaVerified: true,
                mfaVerifiedAt: verifyAt,
            }
        });

        return session;
    }

    async updateSessionHashToken(jti: string, hashedToken: string) {
        const session = await this.prisma.session.update({
            where: { jti },
            data: {
                hashedToken,
            }
        });

        return session;
    }

    async revokedSessionByJti(jti: string): Promise<void> {
        await this.prisma.session.update({
            where: { jti },
            data: { status: SessionStatus.Revoked },
        });
    }

    async revokeSessionByDevice(deviceId: string, reason?: string): Promise<number> {
        const result = await this.prisma.session.updateMany({
            where: { deviceId, status: SessionStatus.Active },
            data: {
                status: SessionStatus.Revoked,
                revokedAt: new Date(),
                revokedReason: reason ?? 'User logout',
            }
        });

        // number of row updated
        return result.count;
    }

    async revokeAllUserSessions(userId: string, reason: string) {
        const result = await this.prisma.session.updateMany({
            where: { userId },
            data: {
                status: SessionStatus.Revoked,
                revokedAt: new Date(),
                revokedReason: reason,
            }
        });

        return result.count;
    }

    async findActiveSessionByUserDevice(userId: string, userDeviceId: string): Promise<Session | null> {
        const session = await this.prisma.session.findFirst({
            where: {
                userId,
                userDeviceId,
                status: SessionStatus.Active,
                expiresAt: { gt: new Date() },
            },
            orderBy: { lastUsedAt: 'desc' }
        });

        if (!session) return null;

        const isExpired = this.mfaService.isSessionExpired({
            issuedAt: session.issuedAt,
            mfaVerifiedAt: session.mfaVerifiedAt ?? session.issuedAt,
            expiresAt: session.expiresAt
        });

        if (isExpired) return null;

        return session;
    }

    async refreshSession(newHashedToken: string, newExpiry: Date, deviceId: string, userId: string) {
        const userDevice = await this.userDeviceService.findUserDevice(userId, deviceId);
        if (!userDevice) throw new NotFoundException('Not found session to refresh');
        
        const verifiedSession = await this.verifySession(userDevice.userDeviceId, userId);
        if (!verifiedSession) throw new UnauthorizedException(`Session is not verified`);

        const newRefreshSession = await this.prisma.session.update({
            where: { jti: verifiedSession.jti },
            data: {
                hashedToken: newHashedToken,
                expiresAt: newExpiry,
                lastUsedAt: new Date(),
                status: SessionStatus.Active,
            }
        });

        return newRefreshSession;
    }

    async findSessionByUserId(userId: string) {
        const session = await this.prisma.session.findFirst({
            where: { userId },
        });

        return session || null;
    }

    async findActiveSessionByUserId(userId: string) {
        const session = await this.prisma.session.findFirst({
            where: {
                userId,
                status: SessionStatus.Active,
                expiresAt: { gt: new Date() },
            },
            orderBy: { issuedAt: 'desc' },
        });

        return session || null;
    }

    async deleteExpiredTokens(): Promise<number> {
        const result = await this.prisma.session.deleteMany({
            where: {
                OR: [
                    { status: SessionStatus.Expired },
                    { expiresAt: { lt: new Date() } },
                ],
            },
        });

        return result.count;
    }
}