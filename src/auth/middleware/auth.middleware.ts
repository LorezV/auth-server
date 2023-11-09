import { Injectable } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { JwtService } from '@nestjs/jwt';
import { PrismaService } from 'src/prisma/prisma.service';
import { Request, Response, NextFunction } from "express";

@Injectable()
export class AuthMiddleware {
    constructor(
        private readonly prismaService: PrismaService,
        private readonly configService: ConfigService,
        private readonly jwtService: JwtService
    ) { }

    async use(req: Request, res: Response, next: NextFunction) {
        const token = this.parseToken(req);

        if (token) {
            try {
                const payload: { sub: number, email: string } = await this.jwtService.verifyAsync(token, {
                    secret: await this.configService.get("jwt.accessSecret"),
                })

                const user = await this.prismaService.user.findUnique({
                    where: { id: payload.sub },
                });

                req["user"] = user;
                return next();
            } catch { }
        }

        req["user"] = null;
        return next();
    }


    parseToken(request: Request) {
        let token = request.headers.authorization;

        if (token) {
            if (token.includes("Bearer ")) {
                token = token.replace("Bearer ", "")
            }
        }

        return token;
    }
}