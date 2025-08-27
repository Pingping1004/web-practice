import { Injectable } from "@nestjs/common";
import nodemailer from 'nodemailer';

@Injectable()
export class MailService {
    private transporter = nodemailer.createTransport({
        host: process.env.SMTP_HOST,
        port: parseInt(process.env.SMTP_PORT || "587"),
        secure: false,
        auth: {
            user: process.env.SMTP_USER,
            pass: process.env.SMTP_PASS,
        },
    });

    async sendPasswordResetEmail(email: string, resetToken: string) {
        await this.transporter.sendMail({
            from: "Practice-auth support department",
            to: email,
            subject: "Reset your password",
            html: `
                <p>You requested a password reset.</p>
                <p>Use this token to reset your password (valid for 10 minutes):</p>
                <h2>${resetToken}</h2>
                <p>If you did not request this, please ignore this email.</p>
            `
        });
    }
}