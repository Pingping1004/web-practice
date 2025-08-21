import { forwardRef, Inject, Injectable, UnauthorizedException } from "@nestjs/common";
import { Session } from "@prisma/client";
import { PrismaService } from "prisma/prisma.service";
import { MfaService } from "src/mfa/mfa.service";
import { SessionPayload } from "src/types/session";

@Injectable()
export class SessionService {
    constructor(
        private readonly prisma: PrismaService,
        @Inject(forwardRef(() => MfaService)) private readonly mfaService: MfaService,
    ) { }

    async createSession(sessionPayload: SessionPayload) {
        const { userId, deviceId, hashedToken } = sessionPayload;
        let session = await this.findActiveSessionByDevice(userId, deviceId);

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

    async findSessionByJti(jti: string): Promise<Session | null> {
        const token = await this.prisma.session.findUnique({
            where: { jti },
        });

        return token;
    }

    async verifySession(jti: string, deviceId: string, userId: string) {
        const session = await this.findActiveSessionByDevice(userId, deviceId);
        if (!session) throw new UnauthorizedException(`Session to verify not found`);

        const now = new Date();
        const mfaVerifiedAt = session.mfaVerified && session.mfaVerifiedAt
            ? session.mfaVerifiedAt
            : session.issuedAt;

        if (session.isRevoked || this.mfaService.isSessionExpired({
            issuedAt: session.issuedAt,
            mfaVerifiedAt,
            expiresAt: session.expiresAt,
        })) {
            throw new UnauthorizedException(`Session revoked or expired`);
        }

        if (deviceId && session.deviceId !== deviceId) {
            throw new UnauthorizedException('Session does not belong to this device');
        }

        if (userId && session.userId !== userId) {
            throw new UnauthorizedException('Session does not belong to this user');
        }

        const verifiedSession = await this.markSessionAsVerify(userId, deviceId, now);
        return verifiedSession;
    }

    async markSessionAsVerify(userId: string, deviceId: string, verifyAt: Date) {
        let session = await this.findActiveSessionByDevice(userId, deviceId);
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

    async revokedSessionByJti(jti: string): Promise<void> {
        await this.prisma.session.update({
            where: { jti },
            data: { isRevoked: true },
        });
    }

    async revokeSessionByDevice(deviceId: string, reason?: string): Promise<number> {
        const result = await this.prisma.session.updateMany({
            where: { deviceId, isRevoked: false },
            data: {
                isRevoked: true,
                isActived: false,
                RevokedAt: new Date(),
                revokedReason: reason ?? 'User logout',
            }
        });

        // number of row updated
        return result.count;
    }

    async findActiveSessionByDevice(userId: string, deviceId: string): Promise<Session | null> {
        const session = await this.prisma.session.findFirst({
            where: {
                userId,
                deviceId,
                isRevoked: false,
                expiresAt: { gt: new Date() },
            },
            orderBy: {
                lastUsedAt: 'desc',
            }
        });

        if (!session) return null;

        const mfaVerifiedAt = session.mfaVerified && session.mfaVerifiedAt
            ? session.mfaVerifiedAt
            : session.issuedAt;

        const isExpired = this.mfaService.isSessionExpired({
            issuedAt: session.issuedAt,
            mfaVerifiedAt,
            expiresAt: session.expiresAt
        });

        if (isExpired) return null;

        return session;
    }

    async refreshSession(newHashedToken: string, newExpiry: Date, deviceId: string, userId: string) {
        const session = await this.findActiveSessionByDevice(userId, deviceId);
        console.log('Session found in refresh session: ', session);
        if (!session) throw new UnauthorizedException(`No session found to refresh`);

        const isSessionVerified = await this.verifySession(session.jti, deviceId, userId);
        if (!isSessionVerified) throw new UnauthorizedException(`Session is not verified`);

        const newRefreshSession = await this.prisma.session.update({
            where: { jti: session.jti },
            data: {
                hashedToken: newHashedToken,
                expiresAt: newExpiry,
                lastUsedAt: new Date(),
                isActived: true,
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
                expiresAt: { gt: new Date() }, // session not expired
            },
            orderBy: { issuedAt: 'desc' },
        });

        return session || null;
    }

    async deleteExpiredTokens(): Promise<number> {
        const result = await this.prisma.session.deleteMany({
            where: {
                OR: [
                    { isRevoked: true },
                    { expiresAt: { lt: new Date() } },
                ],
            },
        });

        return result.count;
    }
}