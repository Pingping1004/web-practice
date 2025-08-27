import { Injectable, NotFoundException } from "@nestjs/common";
import { JwtService } from "@nestjs/jwt";
import { UserService } from "src/users/users.service";
import { v4 as uuidv4 } from 'uuid';
import * as bcrypt from 'bcrypt';
import nodemailer from 'nodemailer';
import { PrismaService } from "prisma/prisma.service";
import { MailService } from "src/mail/mail.service";

@Injectable()
export class ResetPassService {
    constructor(
        private readonly prisma: PrismaService,
        private readonly jwtService: JwtService,
        private readonly userService: UserService,
        private readonly mailService: MailService,
    ) { }

    async requestPasswordReset(email: string) {
        const user = await this.userService.findUserByEmail(email);

        if (user) {
            const resetToken = await this.generateResetToken(user.userId);
            const hashedToken = await bcrypt.hash(resetToken, 10);

            await this.prisma.resetPassword.create({
                data: {
                    userId: user.userId,
                    tokenHash: hashedToken,
                    expiresAt: new Date(Date.now() + 1000 * 60 * 10),
                }
            });

            await this.mailService.sendPasswordResetEmail(email, resetToken);
            return hashedToken;
        }
    }

    async generateResetToken(userId: string): Promise<string> {
        const resetTokenPayload = {
            sub: userId,
            type: 'password_reset',
            jti: uuidv4(),
        };

        const resetToken = await this.jwtService.signAsync(resetTokenPayload, {
            expiresIn: '10m',
        });

        return resetToken;
    }

    async verifyResetToken(resetToken: string) { }

    async resetPassword(resetToken: string, newPassword: string) { }
}