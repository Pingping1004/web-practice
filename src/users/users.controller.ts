import { Controller, Get, Req, UseGuards } from '@nestjs/common';
import { Role, User } from '@prisma/client';
import { UserService } from './users.service';
import { Roles } from 'src/auth/decorator/role.decorator';
import { RolesGuard } from 'src/auth/guard/roles.guard';
import { UserJwtPayload } from 'src/auth/dto/auth.dto';

@Controller('users')
export class UsersController {
    constructor(
        private readonly userService: UserService,
    ) {}

    @Get('profile')
    async getUserProfile(@Req() req): Promise<Omit<User, 'password'>> {
        const { sub: userId } = req.user as UserJwtPayload;
        const user = await this.userService.findUserByUserId(userId);
        return user;
    }

    @UseGuards(RolesGuard)
    @Roles(Role.Admin)
    @Get('admin')
    async getAdminProfile(@Req() req): Promise<{ user: Omit<User, 'password'>; message: string }> {
        const { userId } = req.user;

        const user = await this.userService.findUserByUserId(userId);
        // if (user.role !== Role.Admin) throw new UnauthorizedException('Only admin can access this endpoint');
        return { user, message: 'Successfully fetched admin profile' };
    }
}
