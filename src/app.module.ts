import { Module } from '@nestjs/common';
import { ConfigModule } from '@nestjs/config';
import { AuthModule } from './auth/auth.module';
import { ConfigOptions } from './config';
import { PrismaModule } from './prisma/prisma.module';
import { JwtModule } from '@nestjs/jwt';

@Module({
  imports: [
    JwtModule.register({ global: true }),
    ConfigModule.forRoot(ConfigOptions),
    PrismaModule,
    AuthModule,
  ]
})
export class AppModule {}
