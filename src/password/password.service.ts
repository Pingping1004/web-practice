import { BadRequestException, Injectable, InternalServerErrorException, NotFoundException, UnauthorizedException } from "@nestjs/common";
import { UserService } from "src/users/users.service";
import * as bcrypt from 'bcrypt';
import * as crypto from 'crypto';
import { PrismaService } from "prisma/prisma.service";
import { MailService } from "src/mail/mail.service";
import { addMinutes, subDays } from 'date-fns';

@Injectable()
export class PasswordService {
    private readonly RESET_TOKEN_EXPIRY_MINUTES = 10;

    constructor(
        private readonly prisma: PrismaService,
        private readonly userService: UserService,
        private readonly mailService: MailService,
    ) { }

    async requestPasswordReset(email: string) {
        if (!email || !email.includes('@')) throw new BadRequestException('Invalid email format');

        const user = await this.userService.findUserByEmail(email);
        if (!user) {
            // Add small delay to prevent timing attacks
            await new Promise(resolve => setTimeout(resolve, Math.random() * 100 + 50));
            return { success: true }; // Always return success for security
        }

        // Use transaction to prevent race conditions
        const rawToken = await this.prisma.$transaction(async (tx) => {
            await this.invalidatePreviousToken(user.userId);

            const token = this.generateResetToken();
            const hashedToken = crypto.createHash('sha256').update(token).digest('hex');

            await this.createPasswordReset(user.userId, hashedToken);
            return token;
        });

        try {
            await this.mailService.sendResetPasswordEmail(email, rawToken);
            return { success: true };
        } catch {
            await this.prisma.password.deleteMany({
                where: { userId: user.userId, isActive: true },
            });
            throw new InternalServerErrorException('Failed to send reset email, please try again later');
        }
    }

    async invalidatePreviousToken(userId: string) {
        await this.prisma.password.updateMany({
            where: {
                userId,
                isActive: true,
            },
            data: { usedAt: new Date(), isActive: false }
        });
    }

    async createPasswordReset(userId: string, tokenHash: string) {
        await this.prisma.password.create({
            data: {
                userId,
                tokenHash,
                expiresAt: addMinutes(new Date(), this.RESET_TOKEN_EXPIRY_MINUTES),
                isActive: true,
            }
        });
    }

    generateResetToken(): string {
        return crypto.randomBytes(32).toString('hex');
    }

    async findResetRecordForUser(tokenHash: string) {
        const record = await this.prisma.password.findFirst({
            where: {
                tokenHash,
                isActive: true,
                expiresAt: { gt: new Date() },
            },
            orderBy: { createdAt: 'desc' },
        });

        return record;
    }

    async resetPassword(rawToken: string, newPassword: string) {
        const hashedToken = crypto.createHash('sha256').update(rawToken).digest('hex');

        const resetRecord = await this.findResetRecordForUser(hashedToken);
        if (!resetRecord) throw new NotFoundException('No reset request found');

        await this.prisma.$transaction(async (tx) => {
            await this.verifyAndMarkResetToken(resetRecord.tokenHash, resetRecord.userId);
            await this.userService.updateUserPassword(resetRecord.userId, newPassword);
        });

        return { success: true };
    }

    async verifyAndMarkResetToken(hashedToken: string, userId: string) {
        const updated = await this.prisma.password.updateMany({
            where: {
                tokenHash: hashedToken,
                userId,
                isActive: true,
                expiresAt: { gt: new Date() }
            },
            data: {
                usedAt: new Date(),
                isActive: false,
            }
        });

        if (updated.count === 0) throw new UnauthorizedException('Token already used or invalid');
        return updated;
    }

    async cleanupExpiredResetTokens() {
        const result = await this.prisma.password.deleteMany({
            where: {
                OR: [
                    { expiresAt: { lt: new Date() } },
                    {
                        usedAt: { not: null },
                        createdAt: { lt: subDays(new Date(), 1) } // Keep used tokens for 24h
                    }
                ]
            }
        });

        return result.count;
    }
}