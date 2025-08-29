import { Injectable, InternalServerErrorException } from "@nestjs/common";
import nodemailer from 'nodemailer';
import sgMail from '@sendgrid/mail';

@Injectable()
export class MailService {
    // private transporter = nodemailer.createTransport({
    //     host: "smtp.sendgrid.net",
    //     port: parseInt(process.env.SMTP_PORT || "587"),
    //     secure: false,
    //     auth: {
    //         user: "apikey",
    //         pass: process.env.SENDGRID_API_KEY,
    //     },
    // });

    constructor() {
        sgMail.setApiKey(process.env.SENDGRID_API_KEY!);
    }

    // async sendPasswordResetEmail(email: string, resetToken: string) {
    //     try {
    //         const info = await this.transporter.sendMail({
    //             from: ' "Practice-auth support" <moodfee01@gmail.com>',
    //             to: email,
    //             subject: "Reset your password, do not reply",
    //             html: `
    //                 <p>You requested a password reset.</p>
    //                 <p>Use this token to reset your password (valid for 10 minutes):</p>
    //                 <h2>${resetToken}</h2>
    //                 <p>If you did not request this, please ignore this email.</p>
    //                 `
    //         });

    //         console.log('Successfully send password reset email: ', info.messageId);
    //     } catch (error) {
    //         console.error('Failed to send password reset email: ', error.message, error.stack);
    //         throw new InternalServerErrorException('Failed to send email: ', error);
    //     }
    // }

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
            console.log('Successfully send reset password email');
        } catch (error) {
            console.error('Failed to send password reset email: ', error.message, error.stack);
            throw new InternalServerErrorException('Failed to send email: ', error);
        }
    }
}