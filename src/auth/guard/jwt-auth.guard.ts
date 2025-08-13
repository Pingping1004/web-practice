import { ExecutionContext, Injectable, UnauthorizedException } from "@nestjs/common";
import { Reflector } from "@nestjs/core";
import { AuthGuard } from "@nestjs/passport";
import { isObservable, lastValueFrom } from "rxjs";
import { IS_PUBLIC_KEY } from "../decorator/public.decorator";

@Injectable()
export class JwtAuthGuard extends AuthGuard('jwt') {
    constructor(
        private readonly reflector: Reflector,
    ) {
        super();
    }

    async canActivate(context: ExecutionContext): Promise<boolean> {
        const isPublic = this.reflector.getAllAndOverride<boolean>(IS_PUBLIC_KEY, [
            context.getHandler(),
            context.getClass(),
        ]);

        if (isPublic) return true;

        const result = super.canActivate(context);
        if (result instanceof Promise) {
            return await result;
        } else if (isObservable(result)) {
            return await lastValueFrom(result);
        } else {
            return result;
        }
    }

    handleRequest<TUser = any>(
        err: any, user: any, info: any, context: ExecutionContext, status?: any
    ): TUser {
        if (err || !user) throw err || new UnauthorizedException();
        return user;
    }
}