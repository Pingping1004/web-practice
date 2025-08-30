import { ExecutionContext, Injectable, NotFoundException, UnauthorizedException } from "@nestjs/common";
import { Reflector } from "@nestjs/core";
import { AuthGuard } from "@nestjs/passport";
import { IS_PUBLIC_KEY } from "../decorator/public.decorator";
import { UserJwtPayload } from "../dto/auth.dto";
import { SessionService } from "src/session/session.service";
import { SessionStatus } from "@prisma/client";
import { UserDeviceService } from "src/userDevice/userDevice.service";
import { LoggingService } from "src/logging/logging.service";

@Injectable()
export class JwtAuthGuard extends AuthGuard('jwt') {
    constructor(
        private readonly reflector: Reflector,
        private readonly sessionService: SessionService,
        private readonly userDeviceService: UserDeviceService,
        private readonly logger: LoggingService,
    ) {
        super();
    }

    async canActivate(context: ExecutionContext): Promise<boolean> {
        const isPublic = this.reflector.getAllAndOverride<boolean>(IS_PUBLIC_KEY, [
            context.getHandler(),
            context.getClass(),
        ]);

        if (isPublic) return true;

        const req = context.switchToHttp().getRequest();
        const result = await super.canActivate(context);

        const user = req.user as UserJwtPayload;
        this.logger.audit(`JWT payload`, { user: req.user });
        if (!user || !user.deviceId) {
            throw new UnauthorizedException('Missing deviceId in token');
        }

        const userDevice = await this.userDeviceService.findUserDevice(user.sub, user.deviceId);
        if (!userDevice) throw new NotFoundException('User device in JWT guard not found');

        const session = await this.sessionService.findActiveSessionByUserDevice(user.sub, userDevice?.userDeviceId);
        if (!session || session?.status !== SessionStatus.Active) 
            throw new UnauthorizedException(`Session revoked or invalid device`);

        return true;
    }

    handleRequest<TUser = any>(
        err: any, user: any, info: any, context: ExecutionContext, status?: any
    ): TUser {
        if (err || !user) throw err || new UnauthorizedException();
        return user;
    }
}