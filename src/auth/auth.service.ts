import { BadRequestException, ConflictException, Injectable, NotFoundException, UnauthorizedException } from '@nestjs/common';
import { PrismaService } from 'src/prisma/prisma.service';
import { ConfigService } from '@nestjs/config';
import { JwtService } from '@nestjs/jwt';
import { compare, hash } from 'bcrypt';

@Injectable()
export class AuthService {
    constructor(
        private readonly prismaService: PrismaService,
        private readonly configService: ConfigService,
        private readonly jwtService: JwtService
    ) { }

    public async signIn(email: string, password: string) {
        const user = await this.prismaService.user.findUnique({
            where: { email },
        });

        if (!user || !await compare(password, user.password)) {
            throw new UnauthorizedException();
        }

        return await this.generateTokens({
            sub: user.id,
            email: user.email
        });
    }

    public async signUp(email: string, password: string) {
        const candidate = await this.prismaService.user.findUnique({
            where: { email },
        });

        if (candidate) {
            throw new ConflictException();
        }

        const user = await this.prismaService.user.create({
            data: {
                email,
                password: await hash(password, 10),
            }
        });

        return await this.generateTokens({
            sub: user.id,
            email: user.email
        });
    }

    public async refreshToken(refreshToken: string) {
        let payload: { sub: number } | undefined;

        try {
            payload = await this.jwtService.verifyAsync(refreshToken, {
                secret: this.configService.get<string>('JWT_REFRESH_SECRET'),
            });
        } catch {
            throw new BadRequestException();
        }

        const user = await this.prismaService.user.findUnique({
            where: { id: payload.sub },
        });

        if (!user) {
            throw new NotFoundException();
        }

        return await this.generateTokens({
            sub: user.id,
            email: user.email
        });
    }

    public async generateTokens(payload: { sub: number, email: string }) {
        const [accessToken, refreshToken]: [string, string] = await Promise.all([
            this.jwtService.signAsync(payload, {
                secret: await this.configService.get('JWT_ACCESS_SECRET'),
                expiresIn: await this.configService.get('JWT_ACCESS_TIME')
            }),
            this.jwtService.signAsync(payload, {
                secret: await this.configService.get('JWT_REFRESH_SECRET'),
                expiresIn: await this.configService.get('JWT_ACCESS_TIME')
            }),
        ]);

        return { accessToken, refreshToken }
    }

}
