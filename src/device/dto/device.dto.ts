import { BanSeverity, DeviceStatus, TrustLevel } from "@prisma/client";
import { IsString, IsNotEmpty, IsUUID, IsOptional, IsEnum, IsDate } from "class-validator";

export class RegisterDeviceDto {
    @IsUUID()
    @IsNotEmpty()
    userId: string;

    @IsString()
    @IsNotEmpty()
    ipAddress: string;

    @IsString()
    @IsNotEmpty()
    deviceHash: string;

    @IsEnum(DeviceStatus)
    @IsNotEmpty()
    deviceStatus: DeviceStatus;

    @IsEnum(TrustLevel)
    @IsOptional()
    trustLevel?: TrustLevel;

    @IsEnum(BanSeverity)
    @IsOptional()
    banSeverity?: BanSeverity;

    @IsDate()
    @IsOptional()
    expiresAt?: Date;
}