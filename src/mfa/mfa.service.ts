import { BadRequestException, forwardRef, Inject, Injectable, InternalServerErrorException, UnauthorizedException } from "@nestjs/common";
import * as speakeasy from 'speakeasy';
import * as qrcode from 'qrcode';
import * as bcrypt from 'bcrypt'
import { UsersService } from "src/users/users.service";
import { DeviceStatus, MfaMethod, TrustLevel } from "@prisma/client";
import { createCipheriv, createDecipheriv, randomBytes } from "crypto";
import { v4 as uuidv4 } from 'uuid';
import { JwtService } from "@nestjs/jwt";
import { AuthService } from "src/auth/auth.service";
import { UserJwtPayload } from "src/auth/dto/auth.dto";
import { PendingMfaPayload } from "src/types/session";
import { SessionService } from "src/session/session.service";
import { DeviceService } from "src/device/device.service";

@Injectable()
export class MfaService {
    private readonly ALGORITHM = 'aes-256-gcm';
    private readonly IV_LENGTH = 12;
    private readonly KEY: Buffer;

    constructor(
        private readonly userService: UsersService,
        private readonly jwtService: JwtService,
        private readonly deviceService: DeviceService,
        @Inject(forwardRef(() => SessionService)) private readonly sessionService: SessionService,
        @Inject(forwardRef(() => AuthService)) private readonly authService: AuthService,
    ) {
        const keyString = process.env.ENCRYPTION_KEY;
        if (!keyString) {
            throw new Error('Missing ENCRYPTION_KEY env variable');
        }
        this.KEY = Buffer.from(keyString, 'hex');
    }
    async generateMfaSecret(userId: string) {
        console.log('Generate MFA secret is activated');
        const { username, mfaEnabled, mfaSecret } = await this.userService.findUserByUserId(userId);

        if (mfaEnabled && mfaSecret) return { alreadyConfigured: true as const }

        const secret = speakeasy.generateSecret({ name: `Practice-auth : ${username}`, length: 20});

        const encryptedSecret = this.encryptedSecret(secret.base32);
        await this.userService.updateMfaAuth(userId, MfaMethod.Totp, encryptedSecret);

        if (!secret.otpauth_url) throw new InternalServerErrorException('Failed to generate OTP Auth URL')
        const qrCodeUrl = await this.generateTotpQr(secret.otpauth_url, 400);
        return {
            base32: secret.base32,
            otpauthUrl: secret.otpauth_url,
            qrCodeUrl,
        }
    }

    async generateTotpQr(otpauthUrl: string, size: number = 300): Promise<string> {
        const qrCodeUrl = await qrcode.toDataURL(otpauthUrl, {
            width: size
        });
        return qrCodeUrl;
    }

    async validateTotp(userId: string, userTotp: string, ipAddress: string, userAgent: string, deviceId: string) {
        const { mfaSecret: encryptedSecret } = await this.userService.findUserByUserId(userId);
        console.log('Encrypted secret from DB before decrypt:', encryptedSecret);

        if (!encryptedSecret) throw new UnauthorizedException('MFA not setup for this user');

        const secret = this.decryptSecret(encryptedSecret);
        console.log('Decrypted secret: ', secret);
        console.log('userTotp: ', userTotp);

        const isTotpValid = speakeasy.totp.verify({
            secret,
            encoding: 'base32',
            token: userTotp,
            window: 2,
        });

        if (!isTotpValid) throw new UnauthorizedException('Invalid 6-digit code');

        const { accessToken, refreshToken, jti } = await this.generateFinalToken(userId, true, ipAddress, userAgent, deviceId);
        return { accessToken, refreshToken, jti };
    }

    async generateFinalToken(userId: string, isVerified: boolean, ipAddress: string, userAgent: string, deviceId: string, existingJti?: string) {
        if (!isVerified) throw new BadRequestException('MFA verification required');

        let device = await this.deviceService.findDeviceById(deviceId);
        if (!device) {
            device = await this.deviceService.registerDevice(userId, ipAddress, userAgent, deviceId)
        } else {
            await this.deviceService.updateMfaTrusted(deviceId);
        }

        console.log('Device ID from params: ', deviceId);
        console.log('Device ID from device: ', device.deviceId);

        const { email, role } = await this.userService.findUserByUserId(userId);
        const sessionJti = existingJti || uuidv4();

        const userPayload: UserJwtPayload = {
            sub: userId,
            email: email,
            role: role,
            userId,
            jti: sessionJti,
            deviceId,
        };

        const { accessToken, refreshToken } = await this.authService.generateToken(userPayload, sessionJti);

        const expiresAt = new Date(Date.now() + 30 * 24 * 60 * 60 * 1000);
        const hashingToken = await bcrypt.hash(refreshToken, 10);

        await this.sessionService.createSession({
            jti: sessionJti,
            hashedToken: hashingToken,
            userId,
            expiresAt,
            ipAddress,
            // deviceId: device.deviceId,
            deviceId,
            mfaVerified: isVerified,
        });

        return { accessToken, refreshToken, jti: sessionJti };
    }

    async generatePendingToken(userId: string): Promise<string> {
        const tempPayload = {
            sub: userId,
            type: 'pending_mfa',
            jti: uuidv4(),
        };

        const pendingToken = await this.jwtService.signAsync(tempPayload, {
            expiresIn: '3m',
        });

        return pendingToken;
    }

    async verifyPendingToken(token: string): Promise<PendingMfaPayload> {
        try {
            const decoded = await this.jwtService.verifyAsync<PendingMfaPayload>(token);

            if (decoded.type !== 'pending_mfa') {
                throw new UnauthorizedException('Invalid token type for MFA');
            }

            return decoded;
        } catch {
            throw new UnauthorizedException('Invalid or expired MFA token');
        }
    }

    isSessionExpired(session: { issuedAt: Date; mfaVerifiedAt?: Date, expiresAt: Date }): boolean {
        const THIRTY_DAYS = 30 * 24 * 60 * 60 * 1000;

        const now = Date.now();
        const issuedTime = new Date(session.issuedAt).getTime();
        const expiresAtTime = session.expiresAt.getTime();

        if (now > expiresAtTime) return true;

        const mfaTime = session.mfaVerifiedAt?.getTime() ?? issuedTime;
        if (now - mfaTime > THIRTY_DAYS) return true;

        return false;
    }


    encryptedSecret(secret: string): string {
        console.log('Input secret: ', secret);
        const iv = randomBytes(this.IV_LENGTH);
        const cipher = createCipheriv(this.ALGORITHM, this.KEY, iv);

        const encrypted = Buffer.concat([cipher.update(secret, 'utf-8'), cipher.final()]);
        const authTag = cipher.getAuthTag();

        const result = `${iv.toString('base64')}.${authTag.toString('base64')}.${encrypted.toString('base64')}`;
        console.log('Encrypted result:', result);
        return result;
    }

    decryptSecret(encryptedText: string): string {
        console.log('Input to decrypt: ', encryptedText);
        const [ivB64, authTagB64, encryptedB64] = encryptedText.split('.');
        if (!ivB64 || !authTagB64 || !encryptedB64) throw new Error('Invalid MFA secret format');

        try {
            const iv = Buffer.from(ivB64, 'base64');
            const authTag = Buffer.from(authTagB64, 'base64');
            const encrypted = Buffer.from(encryptedB64, 'base64');

            const decipher = createDecipheriv(this.ALGORITHM, this.KEY, iv);
            decipher.setAuthTag(authTag);

            const decrypted = Buffer.concat([decipher.update(encrypted), decipher.final()]);
            const result = decrypted.toString('utf-8');
            console.log('Decrypted result: ', result);
            return result;
        } catch (error) {
            console.error('Decrypted failed: ', error.message);
            throw new Error('Failed to decrypt secret');
        }
    }
}