import { IsString, IsJWT } from 'class-validator';

export class RefreshTokenDto {
    @IsString()
    @IsJWT()
    refreshToken: string
}