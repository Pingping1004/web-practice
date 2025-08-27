import { ExtractJwt, Strategy } from "passport-jwt";
import { PassportStrategy } from "@nestjs/passport";
import { Injectable, Logger, UnauthorizedException } from "@nestjs/common";
import { jwtConstants } from "../constant";
import { UserService } from "src/users/users.service";
import { Role } from "@prisma/client";
import type { Request } from "express";

@Injectable()
export class JwtStrategy extends PassportStrategy(Strategy, 'jwt') {
    private readonly logger = new Logger('JwtStrategy');
    constructor(
        private readonly userService: UserService,
    ) {
        super({
            jwtFromRequest: ExtractJwt.fromExtractors([
                (req: Request) => {
                    return req?.cookies?.access_token;
                },
            ]),
            secretOrKey: jwtConstants.secret,
            ignoreExpiration: false,
            passReqToCallback: true,
        });
    }

    async validate(req: Request, payload: { sub: string, email: string, role: Role, jti: string, deviceId: string, sessionId: string }) {
        const cookieDeviceId = req.cookies?.deviceId;

        if (!cookieDeviceId || cookieDeviceId !== payload.deviceId) {
            throw new UnauthorizedException('Device mismatch');
        }

        try {
            await this.userService.findUserByUserId(payload.sub);
            return {
                sub: payload.sub,
                email: payload.email,
                role: payload.role,
                jti: payload.jti,
                deviceId: payload.deviceId,
                sessionId: payload.sessionId,
            };
        } catch (error) {
            this.logger.warn(`User not found or error in JWT validate: ${error.message}`);
            return null;
        }
    }
}