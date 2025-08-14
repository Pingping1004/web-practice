import { CanActivate, ExecutionContext, ForbiddenException, Injectable } from "@nestjs/common";
import { Reflector } from "@nestjs/core";
import { ROLES_KEY } from "../decorator/role.decorator";
import { IS_PUBLIC_KEY } from "../decorator/public.decorator";

@Injectable()
export class RolesGuard implements CanActivate {
    constructor (private readonly reflector: Reflector) {}

    canActivate(context: ExecutionContext): boolean {
        const requiredRoles = this.reflector.getAllAndOverride<string[]>(ROLES_KEY, [
            context.getHandler(),
            context.getClass()
        ]);

        const isPublic = this.reflector.getAllAndOverride<boolean>(IS_PUBLIC_KEY, [
            context.getHandler(),
            context.getClass(),
        ]);

        if (isPublic) return true;
        if (!requiredRoles || requiredRoles.length === 0) throw new ForbiddenException('No roles defined for this endpoint');

        const request = context.switchToHttp().getRequest();
        const user = request.user;

        if (!user) {
            throw new ForbiddenException('No user found in request');
        }

        if (!user.role) {
            throw new ForbiddenException('This endpoint requires specific roles, but none were defined');
        }

        if (!requiredRoles.includes(user.role)) {
            throw new ForbiddenException(`Your role is not allowed to access this endpoint`);
        }

        // return requiredRoles.includes(userRole)
        return true;
    }
}