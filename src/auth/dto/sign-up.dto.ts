import { IsEmail, IsString, IsStrongPassword } from 'class-validator'

export class SignUpDto {
    @IsString()
    @IsEmail()
    email: string

    @IsString()
    @IsStrongPassword()
    password: string

    @IsString()
    @IsStrongPassword()
    passwordRepeat: string
}