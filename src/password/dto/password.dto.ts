import { IsEmail, IsNotEmpty, IsString } from "class-validator";

export class RequestResetPassDto {
    @IsEmail()
    @IsNotEmpty()
    email: string;
}

export class ResetPassDto {
    @IsString()
    @IsNotEmpty()
    resetToken: string;

    @IsString()
    @IsNotEmpty()
    newPassword: string;
}