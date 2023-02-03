import { Injectable } from "@nestjs/common";

@Injectable({})
export class AuthService{
    signin(){
        return 'User signed in';
    }
    signup(){
        return 'User signed up';
    }
}