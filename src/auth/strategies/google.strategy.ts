import { Injectable, Logger } from "@nestjs/common";
import { PassportStrategy } from "@nestjs/passport";
import { AuthProvider } from "@prisma/client";
import { VerifyCallback, Strategy } from 'passport-google-oauth20'
import { OauthService } from "src/oauth/oauth.service";

@Injectable()
export class GoogleStrategy extends PassportStrategy(Strategy, 'google') {
    private readonly logger = new Logger('GoogleStrategy');
    constructor(
        private readonly oauthService: OauthService,
    ) {
        super({
            clientID: process.env.GOOGLE_CLIENT_ID,
            clientSecret: process.env.GOOGLE_CLIENT_SECRET,
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
            const { id: googleId, emails, } = profile;
            const { givenName } = profile.name;

            const oauthAccount = await this.oauthService.findOauthAccount(AuthProvider.Google, googleId);
            if (oauthAccount) return done(null, oauthAccount)

            const newUserPayload = {
                username: givenName,
                emails,
                provider: AuthProvider.Google,
                googleId,
            };

            done(null, newUserPayload);
        } catch (error) {
            return done(error, false);
        }
    }
}