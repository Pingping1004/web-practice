import { Controller, Get, Req } from '@nestjs/common';
import { User } from '@prisma/client';
import { UsersService } from './users.service';

@Controller('users')
export class UsersController {
    constructor(
        private readonly usersService: UsersService,
    ) {}

    @Get('profile')
    async getUserProfile(@Req() req): Promise<Omit<User, 'password'>> {
        const userId = req.user.userId;
        const user = await this.usersService.findUserByUserId(userId);
        return user;
    }
}
