import { ExecutionContext, Injectable } from "@nestjs/common";
import { AuthGuard } from "@nestjs/passport";

@Injectable()
export class GoogleAuthGuard extends AuthGuard('google') {
    getAuthenticateOptions(context: ExecutionContext) {
        return {
            scope: ['email', 'profile'],
            prompt: 'select_account',
        }
    }
}