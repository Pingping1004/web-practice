import { Injectable, Logger, UnauthorizedException } from '@nestjs/common';
import { User } from '@prisma/client';
import { UsersService } from 'src/users/users.service';
import * as bcrypt from 'bcrypt';

@Injectable()
export class AuthService {
    constructor(
        private readonly userService: UsersService,
    ) {}

    private readonly logger = new Logger('AuthService');
    
    async validateUser(email: string, password: string): Promise<Omit<User, 'password'>> {
        const DUMMY_HASH = '$2b$10$CwTycUXWue0Thq9StjUM0uJ8e3zoH8JPB8OPm0.9l4qwEYAsfP0r6';
        const user = await this.userService.findUserByEmail(email);
        let passwordIsValid: boolean = false;

        if (user?.password) {
            passwordIsValid = await bcrypt.compare(password, user.password);
        } else {
            await bcrypt.compare(password, DUMMY_HASH);
            console.warn('Login attempt for non-existent email: ', email);
        }

        if (!passwordIsValid || !user) throw new UnauthorizedException('Password is incorrect');

        const { password: _, ...result } = user;
        return result;
    }
}