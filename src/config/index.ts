import * as Joi from 'joi';
import { ConfigModuleOptions } from '@nestjs/config';

export const ConfigOptions: ConfigModuleOptions = {
    isGlobal: true,
    validationSchema: Joi.object({
        JWT_ACCESS_TIME: Joi.string().required(),
        JWT_ACCESS_SECRET: Joi.string().required(),
        JWT_REFRESH_TIME: Joi.string().required(),
        JWT_REFRESH_SECRET: Joi.string().required(),
    }),
}