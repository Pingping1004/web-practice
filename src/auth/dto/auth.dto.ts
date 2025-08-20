import { Role } from "@prisma/client";
import { IsDate, IsEmail, IsEnum, IsNotEmpty, IsOptional, IsString } from "class-validator";

export class SignupDto {
    @IsString()
    @IsNotEmpty()
    username: string;

    @IsEmail()
    @IsOptional()
    email?: string;

    @IsString()
    @IsOptional()
    password?: string;
}

export class LoginDto {
    @IsString()
    @IsOptional()
    username?: string;

    @IsEmail()
    @IsOptional()
    email?: string;

    @IsString()
    @IsOptional()
    password?: string;

    @IsString()
    @IsOptional()
    deviceId?: string;
}

export class UserPayloadDto {
    @IsString()
    @IsNotEmpty()
    sub: string;

    @IsString()
    @IsNotEmpty()
    email: string;

    @IsEnum(Role)
    @IsNotEmpty()
    role: Role;

    @IsString()
    @IsNotEmpty()
    userId: string;

    @IsDate()
    @IsOptional()
    mfaVerifiedAt?: Date | null;
}

export interface UserJwtPayload extends UserPayloadDto {
    jti: string;
}