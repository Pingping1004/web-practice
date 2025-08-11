import { AuthProvider } from "@prisma/client";
import { IsEnum, IsNotEmpty, IsString } from "class-validator";

export class OauthDto {
    @IsEnum(AuthProvider)
    @IsNotEmpty()
    provider: AuthProvider;

    @IsString()
    @IsNotEmpty()
    providerUserId: string;

    @IsString()
    @IsNotEmpty()
    userId: string;
}