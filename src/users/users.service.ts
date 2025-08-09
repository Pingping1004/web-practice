import { ConflictException, Injectable, NotFoundException } from '@nestjs/common';
import { PrismaService } from 'prisma/prisma.service';
import { User } from '@prisma/client';

@Injectable()
export class UsersService {
    constructor(
        private readonly prisma: PrismaService,
    ) {}

    async createuser(user: User): Promise<User> {
        const existingUser = await this.findUserByUserName(user.userId);
        if (existingUser) throw new ConflictException('User already register');

        const result = await this.prisma.user.create({
            data: user,
        });

        return result;
    }

    async findUserByUserId(userId: string): Promise<Omit<User, 'password'>> {
        const user = await this.prisma.user.findUnique({
            where: { userId },
        });

        if (!user) throw new NotFoundException('User not found')

        const { password, ...result } = user;
        return result;
    }

    async findUserByUserName(username: string): Promise<Omit<User, 'password'> | null> {
        const user = await this.prisma.user.findUnique({
            where: { username },
        });

        if (!user) return null;

        const { password, ...result } = user;
        return result;
    }

    async findUserByEmail(email: string): Promise<User| null> {
        const user = await this.prisma.user.findUnique({
            where: { email },
        });

        return user;
    }
}