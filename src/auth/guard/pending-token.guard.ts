import { CanActivate, ExecutionContext, Injectable, UnauthorizedException } from "@nestjs/common";
import { MfaService } from "src/mfa/mfa.service";

@Injectable()
export class PendingTokenGuard implements CanActivate {
    constructor(private readonly mfaService: MfaService) {}

    async canActivate(context: ExecutionContext): Promise<boolean> {
        const req = context.switchToHttp().getRequest();
        const pendingToken = req.cookies?.pending_token || req.body.pendingToken;
        
        if (!pendingToken) throw new UnauthorizedException('Pending token missing');

        try {
            const { sub: userId } = await this.mfaService.verifyPendingToken(pendingToken);
            req.user = { sub: userId };
            return true;
        } catch {
            throw new UnauthorizedException('Invalid or expired pending token');
        }
    }
}