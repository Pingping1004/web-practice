import { Controller, Get, Req, UnauthorizedException, UseGuards } from '@nestjs/common';
import { Role, User } from '@prisma/client';
import { UsersService } from './users.service';
import { Roles } from 'src/auth/decorator/role.decorator';
import { RolesGuard } from 'src/auth/guard/roles.guard';

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

    @UseGuards(RolesGuard)
    @Roles(Role.Admin)
    @Get('admin')
    async getAdminProfile(@Req() req): Promise<{ user: Omit<User, 'password'>; message: string }> {
        const { userId } = req.user;
        console.log('userId: ', userId);

        const user = await this.usersService.findUserByUserId(userId);
        // if (user.role !== Role.Admin) throw new UnauthorizedException('Only admin can access this endpoint');
        return { user, message: 'Successfully fetched admin profile' };
    }
}
