import { Injectable, InternalServerErrorException } from "@nestjs/common";
import sgMail from '@sendgrid/mail';
import { LoggingService } from "src/logging/logging.service";

@Injectable()
export class MailService {
    constructor(
        private readonly logger: LoggingService,
    ) {
        sgMail.setApiKey(process.env.SENDGRID_API_KEY!);
    }

    async sendResetPasswordEmail(email: string, resetToken: string) {
        const message = {
            to: email,
            from: ' "Practice-auth support" <moodfee01@gmail.com>',
            subject: 'Reset your password, do not reply',
            html: `
            <p>You requested a password reset.</p>
            <p>Use this token to reset your password (valid for 10 minutes):</p>
            <h2>${resetToken}</h2>
            <p>If you did not request this, please ignore this email.</p>
            `,
        };

        try {
            await sgMail.send(message);
            this.logger.log('Successfully send reset password email');
        } catch (error) {
            this.logger.error('Failed to send password reset email: ', error.message);
            throw new InternalServerErrorException('Failed to send email: ', error);
        }
    }
}