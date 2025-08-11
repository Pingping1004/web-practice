import { Injectable, Logger } from "@nestjs/common";
import { AuthProvider } from "@prisma/client";
import { PrismaService } from "prisma/prisma.service";
import { OauthDto } from "./dto/oauth.dto";

@Injectable()
export class OauthService {
    private readonly logger = new Logger('OauthService')
    constructor(private readonly prisma: PrismaService) {}
    async createOauthAccount (oauthDto: OauthDto) {
        const oauthUser = await this.prisma.oAuthAccount.create({
            data: {
                provider: oauthDto.provider,
                providerUserId: oauthDto.providerUserId,
                userId: oauthDto.userId,
            }
        });

        return oauthUser;
    }

    async findOauthAccount(provider: AuthProvider, providerUserId: string) {
        const oauthAccount = await this.prisma.oAuthAccount.findUnique({
            where: {
                provider_providerUserId: {
                    provider,
                    providerUserId,
                }
            },
            include: { user: true },
        });

        return oauthAccount;
    }
}