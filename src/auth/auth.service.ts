import { Injectable, Logger, NotFoundException, UnauthorizedException } from '@nestjs/common';
import { User } from '@prisma/client';
import { UsersService } from 'src/users/users.service';
import * as bcrypt from 'bcrypt';
import { LoginDto, SignupDto, UserPayloadDto } from './dto/auth.dto';
import { JwtService } from '@nestjs/jwt';
import { v4 as uuidv4 } from 'uuid';

@Injectable()
export class AuthService {
    constructor(
        private readonly usersService: UsersService,
        private readonly jwtService: JwtService,
    ) { }

    private readonly logger = new Logger('AuthService');

    async validateUser(username: string, password: string): Promise<Omit<User, 'password'>> {
        const DUMMY_HASH = '$2b$10$CwTycUXWue0Thq9StjUM0uJ8e3zoH8JPB8OPm0.9l4qwEYAsfP0r6';
        const user = await this.usersService.findUserByUserName(username);
        console.log('User in validation: ', user);
        let passwordIsValid: boolean = false;

        if (user?.password) {
            passwordIsValid = await bcrypt.compare(password, user.password);
            console.log('Is password valid? ', passwordIsValid);
        } else {
            await bcrypt.compare(password, DUMMY_HASH);
            this.logger.warn('Login attempt for non-existent user: ', username);
        }

        if (!passwordIsValid || !user) throw new UnauthorizedException('Password is incorrect');

        const { password: _, ...result } = user;
        return result;
    }

    private async generateToken(payload: UserPayloadDto) {
        const jti = uuidv4();

        const accessToken = await this.jwtService.signAsync({
            ...payload,
            jti,
        }, { expiresIn: '30m' });

        const refreshToken = await this.jwtService.signAsync({
            ...payload,
            jti,
        }, { expiresIn: '7d' });

        return { accessToken, refreshToken };
    }

    async login(loginDto: LoginDto) {
        if (!loginDto.username) throw new NotFoundException('Username not found in login DTO');
        if (!loginDto.password) throw new NotFoundException('Password not found in login DTO');

        const user = await this.validateUser(loginDto.username, loginDto.password);

        const userPayload: UserPayloadDto = {
            sub: user.userId,
            email: user.email,
            role: user.role,
        };

        const { accessToken, refreshToken } = await this.generateToken(userPayload);

        return {
            userPayload,
            accessToken,
            refreshToken,
        }
    }

    async register(signupDto: SignupDto) {
        const user = await this.usersService.createuser(signupDto);

        const userPayload: UserPayloadDto = {
            sub: user.userId,
            email: user.email,
            role: user.role,
        };

        const { accessToken, refreshToken } = await this.generateToken(userPayload);
        return { user, accessToken, refreshToken };
    }

    async refresh(refreshToken: string) {
        try {
            const payload = await this.jwtService.verifyAsync(refreshToken);
            const newExpiry = new Date(Date.now() + 7 * 24 * 60 * 60 * 1000);

            const user = await this.usersService.findUserByUserId(payload.sub);
            const newUserPayload: UserPayloadDto = {
                sub: user.userId,
                email: user.email,
                role: user.role,
            };

            const { accessToken, refreshToken: newRefreshToken } = await this.generateToken(newUserPayload);

            return {
                accessToken,
                refreshToken: newRefreshToken,
                newUserPayload,
            };
        } catch (error) {
            this.logger.error('Refresh token verification failed: ', error);
            throw new UnauthorizedException('Invalid refresh token');
        }
    }
}