import { Injectable, Logger } from "@nestjs/common";
import { ConfigService } from "@nestjs/config";
import { PassportStrategy } from "@nestjs/passport";
import { AuthProvider } from "@prisma/client";
import { VerifyCallback, Strategy } from 'passport-google-oauth20'
import { OauthService } from "src/oauth/oauth.service";
import { UsersService } from "src/users/users.service";
import { AuthService } from "../auth.service";

@Injectable()
export class GoogleStrategy extends PassportStrategy(Strategy, 'google') {
    private readonly logger = new Logger('GoogleStrategy');
    constructor(
        private readonly configService: ConfigService,
        private readonly userService: UsersService,
        private readonly oauthService: OauthService,
        private readonly authService: AuthService,
    ) {
        super({
            clientID: configService.get('GOOGLE_CLIENT_ID'),
            clientSecret: configService.get('GOOGLE_CLIENT_SECRET'),
            callbackURL: 'http://localhost:4000/auth/google/callback',
            scope: ['email', 'profile'],
        });
    }

    async validate(
        accessToken: string,
        refreshToken: string,
        profile: any,
        done: VerifyCallback,
    ) {
        try {
            const { id: googleId, emails, name } = profile;
            console.log('googleId in google strategy: ', googleId);
            const email = emails?.[0]?.value ?? null;
            const username = typeof name === 'string' ? name : (name?.givenName ?? email.split('@')[0]);

            const oauthAccount = await this.oauthService.findOauthAccount(AuthProvider.Google, googleId);
            if (oauthAccount) return done(null, oauthAccount.user)

            const newUserPayload = {
                username,
                emails,
                provider: AuthProvider.Google,
                googleId,
            };

            return done(null, newUserPayload);
        } catch (error) {
            return done(error, false);
        }
    }
}