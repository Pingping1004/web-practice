import { ConflictException, Injectable, NotFoundException } from '@nestjs/common';
import { PrismaService } from 'prisma/prisma.service';
import { Role, User } from '@prisma/client';
import { SignupDto } from 'src/auth/dto/auth.dto';
import * as bcrypt from 'bcrypt';

@Injectable()
export class UsersService {
    constructor(
        private readonly prisma: PrismaService,
    ) {}

    async createuser(signupDto: SignupDto): Promise<User> {
        const existingUser = await this.findUserByUserName(signupDto.username);
        if (existingUser) throw new ConflictException('User already register');

        let hashedPassword;
        if (signupDto.password) hashedPassword = await bcrypt.hash(signupDto.password, 10);
        const result = await this.prisma.user.create({
            data: {
                email : signupDto.email ?? signupDto.username,
                username: signupDto.username,
                password: hashedPassword ?? '',
                role: Role.User,
            },
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

    async findUserByUserName(username: string): Promise<User | null> {
        const user = await this.prisma.user.findUnique({
            where: { username },
        });

        if (!user) return null;

        // const { password, ...result } = user;
        return user;
    }

    async findUserByEmail(email: string): Promise<User| null> {
        const user = await this.prisma.user.findUnique({
            where: { email },
        });

        return user;
    }
}