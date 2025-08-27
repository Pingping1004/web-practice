import { PartialType } from "@nestjs/mapped-types";
import { BanSeverity, DeviceStatus, TrustLevel } from "@prisma/client";
import { IsBoolean, IsDate, IsEnum, IsNotEmpty, IsOptional, IsString, IsUUID } from "class-validator";

export class CreateUserDeviceDto {
    @IsUUID()
    @IsNotEmpty()
    userId: string;

    @IsUUID()
    @IsNotEmpty()
    deviceId: string;

    @IsEnum(DeviceStatus)
    @IsNotEmpty()
    deviceStatus: DeviceStatus;

    @IsEnum(TrustLevel)
    @IsNotEmpty()
    trustLevel: TrustLevel;
}

export class UpdateUserDeviceDto extends PartialType(CreateUserDeviceDto) {
    @IsEnum(BanSeverity)
    @IsOptional()
    banSeverity?: BanSeverity;

    @IsBoolean()
    @IsOptional()
    isRevoked?: boolean;

    @IsDate()
    @IsOptional()
    revokedAt?: Date;

    @IsString()
    @IsOptional()
    revokedReason?: string;

    @IsBoolean()
    @IsOptional()
    isMfaTrusted?: boolean;

    @IsDate()
    @IsOptional()
    mfaLastVerifiedAt?: Date;

    @IsDate()
    @IsOptional()
    mfaTrustExpiresAt?: Date;

    @IsDate()
    @IsOptional()
    expiresAt?: Date;

    @IsDate()
    @IsOptional()
    lastUsedAt?: Date;
}