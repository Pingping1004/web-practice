import { ExecutionContext, Injectable, UnauthorizedException } from "@nestjs/common";
import { Reflector } from "@nestjs/core";
import { AuthGuard } from "@nestjs/passport";
import { isObservable, lastValueFrom } from "rxjs";
import { IS_PUBLIC_KEY } from "../decorator/public.decorator";
import { UserJwtPayload } from "../dto/auth.dto";
import { SessionService } from "src/session/session.service";

@Injectable()
export class JwtAuthGuard extends AuthGuard('jwt') {
    constructor(
        private readonly reflector: Reflector,
        private readonly sessionService: SessionService,
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
        console.log('JWT payload: ', req.user);
        if (!user || !user.deviceId) {
            throw new UnauthorizedException('Missing deviceId in token');
        }

        const session = await this.sessionService.findActiveSessionByDevice(user.userId, user.deviceId);
        if (!session || session?.isRevoked) {
            throw new UnauthorizedException(`Session revoked or invalid device`);
        }

        return true;
    }

    handleRequest<TUser = any>(
        err: any, user: any, info: any, context: ExecutionContext, status?: any
    ): TUser {
        if (err || !user) throw err || new UnauthorizedException();
        return user;
    }
}