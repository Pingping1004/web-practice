import { SessionStatus } from "@prisma/client";
import { Request } from "express";
import { UserPayloadDto } from "src/auth/dto/auth.dto";

export interface SessionPayload {
    jti: string;
    hashedToken: string;
    userId: string;
    deviceId: string;
    userDeviceId: string;
    lastUsedAt: Date;
    expiresAt: Date;
    status: SessionStatus;
    revokedAt?: Date;
    revokedReason?: string;
    userAgent?: string;
    ipAddress: string;
    mfaVerified?: boolean;
    mfaVerifiedAt?: Date;
};

export interface RequestWithUser extends Request {
    user?: UserPayloadDto;
    userTotp?: string;
}

export interface PendingMfaPayload {
    sub: string;
    type: 'pending_mfa';
    iat?: number;
    exp?: number;
}

export enum MfaRequirementStatus {
    expired,
    required,
    skip
}