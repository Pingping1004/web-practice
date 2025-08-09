import { Injectable } from '@nestjs/common';

export interface User {
    userId: string;
    username?: string;
    email?: string;
    password?: string;
}

@Injectable()
export class UsersService {
    //
}
