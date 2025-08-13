import { Injectable, ExecutionContext } from "@nestjs/common";
import { ThrottlerGuard } from "@nestjs/throttler";

@Injectable()
export class IpThrottlerGuard extends ThrottlerGuard {
    protected async getTracker(req: any): Promise<string> {
        const forwarded = req.headers['x-forwarded-for'];
        if (forwarded) {
            const ips = forwarded.split(',');
            return ips[0].trim();
        }
        
        return req.ip;
    }

    protected getRequestResponse(context: ExecutionContext) {
        const req = context.switchToHttp().getRequest();
        const res = context.switchToHttp().getResponse();

        return { req, res };
    }
}