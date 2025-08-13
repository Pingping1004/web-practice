import { Request } from "express";
import { UserPayloadDto } from "src/auth/dto/auth.dto";

export interface SessionPayload {
    jti: string;
    hashedToken: string;
    userId: string;
    expiresAt: Date;
    isUsed?: boolean;
    isRevoked?: boolean;
    mfaVerified?: boolean;
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