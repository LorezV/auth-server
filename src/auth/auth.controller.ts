import { BadRequestException, Body, Controller, Post } from '@nestjs/common';
import { AuthService } from './auth.service';
import { SignInDto } from './dto/sign-in.dto';
import { SignUpDto } from './dto/sign-up.dto';
import { RefreshTokenDto } from './dto/refresh-token.dto';

@Controller('auth')
export class AuthController {
    constructor(
        private readonly authService: AuthService
    ) { }

    @Post('sign-in')
    async signIn(@Body() dto: SignInDto) {
        return this.authService.signIn(dto.email, dto.password);
    }

    @Post('sign-up')
    async signUp(@Body() dto: SignUpDto) {
        const { password, passwordRepeat } = dto;

        if (password !== passwordRepeat) {
            throw new BadRequestException('Passwords must match');
        }

        return await this.authService.signUp(dto.email, dto.password);
    }

    @Post('refresh-token')
    async refreshToken(@Body() dto: RefreshTokenDto) {
        return this.authService.refreshToken(dto.refreshToken);
    }
}
