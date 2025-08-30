import { BadRequestException, ConflictException, Injectable, NotFoundException } from '@nestjs/common';
import { PrismaService } from 'prisma/prisma.service';
import { AuthProvider, MfaMethod, Role, User } from '@prisma/client';
import { SignupDto } from 'src/auth/dto/auth.dto';
import * as bcrypt from 'bcrypt';
import { OauthService } from 'src/oauth/oauth.service';
import { LoggingService } from 'src/logging/logging.service';

@Injectable()
export class UserService {
    constructor(
        private readonly prisma: PrismaService,
        private readonly oauthService: OauthService,
        private readonly logger: LoggingService,
    ) { }

    async createUser(signupDto: SignupDto, provider: AuthProvider, providerUserId?: string): Promise<User> {
        const existingUser = await this.findUserByEmail(signupDto.email);
        if (existingUser) throw new ConflictException('User already register');

        let hashedPassword;
        if (signupDto.password) hashedPassword = await bcrypt.hash(signupDto.password, 10);
        const result = await this.prisma.user.create({
            data: {
                email: signupDto.email,
                username: `${(signupDto.email).split('@')[0]}`,
                password: hashedPassword ?? '',
                role: Role.User,
                provider: provider,
            },
        });

        if (provider !== AuthProvider.Local && providerUserId) {
            await this.oauthService.createOauthAccount({
                provider,
                providerUserId,
                userId: result.userId,
            });
        }

        return result;
    }

    async findUserByUserId(userId: string): Promise<Omit<User, 'password'>> {
        this.logger.log(`User ID to search user: ${userId}`);
        const user = await this.prisma.user.findUnique({
            where: { userId },
        });

        if (!user) throw new NotFoundException('User not found')

        const { password, ...result } = user;
        return result;
    }

    async findUserByUserName(username: string): Promise<User | null> {
        const user = await this.prisma.user.findUnique({
            where: { username },
        });

        if (!user) return null;

        return user;
    }

    async findUserByEmail(email: string): Promise<User | undefined> {
        const user = await this.prisma.user.findUnique({
            where: { email },
        });

        return user ?? undefined;
    }

    async updateMfaAuth(userId: string, method: MfaMethod, secret: string) {
        await this.prisma.user.update({
            where: { userId },
            data: {
                mfaEnabled: true,
                mfaMethod: method,
                mfaSecret: secret,
            }
        });
    }

    async findUserByUserIdWithPassword(userId: string) {
        const user = await this.prisma.user.findUnique({
            where: { userId },
        });

        if (!user) throw new NotFoundException('User not found');
        return user;
    }

    async updateUserPassword(userId: string, newPassword: string) {
        const { password } = await this.findUserByUserIdWithPassword(userId);
        if (!password) throw new NotFoundException('Old password not found');

        const isSamePassword = await bcrypt.compare(newPassword, password);
        if (isSamePassword) throw new BadRequestException('New password cannot be the same as the old one');

        const newHashedPassword = await bcrypt.hash(newPassword, 12);
        await this.prisma.user.update({
            where: { userId },
            data: {
                password: newHashedPassword,
            }
        });
    }
}