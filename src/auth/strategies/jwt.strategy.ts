import { ExtractJwt, Strategy } from "passport-jwt";
import { PassportStrategy } from "@nestjs/passport";
import { Injectable, Logger } from "@nestjs/common";
import { jwtConstants } from "../constant";
import { UsersService } from "src/users/users.service";
import { Role } from "@prisma/client";

@Injectable()
export class JwtStrategy extends PassportStrategy(Strategy) {
    private readonly logger = new Logger('JwtStrategy');
    constructor(
        private readonly usersService: UsersService
    ) {
        super({
            jwtFromRequest: ExtractJwt.fromAuthHeaderAsBearerToken(),
            ignoreExpiration: false,
            secretOrKey: jwtConstants.secret,
        });
    }

    async validate(payload: { sub: string, email: string, role: Role }) {
        try {
            await this.usersService.findUserByUserId(payload.sub)
            return { userId: payload.sub, email: payload.email, role: payload.role };
        } catch (error) {
            this.logger.warn(`User not found or error in JWT validate: ${error.message}`);
            return null;
        }
    }
}