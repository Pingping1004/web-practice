import { Injectable } from "@nestjs/common";
import { Session } from "@prisma/client";
import { PrismaService } from "prisma/prisma.service";
import { SessionPayload } from "src/types/session";

@Injectable()
export class SessionService {
    constructor(
        private readonly prisma: PrismaService,
    ) { }

    async createSession(sessionPayload: SessionPayload) {
        const newSession = await this.prisma.session.create({
            data: sessionPayload,
        });

        return newSession;
    }

    async findSessionByJti(jti: string): Promise<Session | null> {
        const token = await this.prisma.session.findUnique({
            where: { jti },
        });

        return token;
    }

    async revokedSessionByJti(jti: string): Promise<void> {
        await this.prisma.session.update({
            where: { jti },
            data: { isRevoked: true },
        });
    }

    async refreshSession(jti: string, newHashedToken: string, newExpiry: Date) {
        const newRefreshSession = await this.prisma.session.update({
            where: { jti },
            data: {
                hashedToken: newHashedToken,
                expiresAt: newExpiry,
                isUsed: false,
            }
        });

        return newRefreshSession;
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