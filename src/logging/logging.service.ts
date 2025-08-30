import { Injectable } from "@nestjs/common";
import 'winston-daily-rotate-file';
import * as winston from 'winston';
import * as fs from 'fs'
import path from 'path';

@Injectable()
export class LoggingService {
    private readonly appLogger: winston.Logger;
    private readonly auditLogger: winston.Logger;

    constructor() {
        const appLogDir = path.join(process.cwd(), 'logs/app');
        const auditLogDir = path.join(process.cwd(), 'logs/audit');

        if (!fs.existsSync(appLogDir)) fs.mkdirSync(appLogDir, { recursive: true });
        if (!fs.existsSync(auditLogDir)) fs.mkdirSync(auditLogDir, { recursive: true });

        // Application logs (general app behavior, errors, debug)
        this.appLogger = winston.createLogger({
            level: process.env.LOG_LEVEL || 'info',
            format: winston.format.combine(
                winston.format.timestamp({ format: 'YYYY-MM-DD HH:mm:ss' }),
                winston.format.errors({ stack: true }),
                winston.format.splat(),
            ),
            transports: [
                new winston.transports.Console({
                    format: winston.format.combine(
                        winston.format.colorize(),
                        winston.format.printf(({ level, message, timestamp, stack, ...meta }) => {
                            let metaStr = Object.keys(meta).length ? JSON.stringify(meta, null, 2) : '';
                            let msg = stack || message;
                            if (typeof msg === 'object') msg = JSON.stringify(msg, null, 2);
                            return `[${timestamp}] ${level}: ${msg} ${metaStr}`;
                        }),
                    ),
                }),

                // File (strict JSON)
                new winston.transports.DailyRotateFile({
                    dirname: 'logs/app',
                    filename: 'app-%DATE%.log',
                    datePattern: 'YYYY-MM-DD HH:mm:ss',
                    zippedArchive: true,
                    maxSize: '20m',
                    maxFiles: '14d',
                    format: winston.format.combine(
                        winston.format.timestamp({ format: 'YYYY-MM-DD HH:mm:ss' }),
                        winston.format.printf(({ level, message, timestamp, stack, ...meta }) => {
                            let metaStr = Object.keys(meta).length ? JSON.stringify(meta, null, 2) : '';
                            let msg = stack || message;
                            if (typeof msg === 'object') msg = JSON.stringify(msg, null, 2);
                            return `[${timestamp}] ${level}: ${msg} ${metaStr}`;
                        }),
                    ),
                }),
            ],
        });

        // Audit logs (auth, sensitive actions, compliance)
        this.auditLogger = winston.createLogger({
            level: 'info',
            format: winston.format.combine(
                winston.format.timestamp({ format: 'YYYY-MM-DD HH:mm:ss' }),
                winston.format.errors({ stack: true }),
                winston.format.splat(),
            ),
            transports: [
                new winston.transports.DailyRotateFile({
                    dirname: 'logs/audit',
                    filename: 'audit-%DATE%.log',
                    datePattern: 'YYYY-MM-DD HH:mm:ss',
                    zippedArchive: true,
                    maxSize: '10m',
                    maxFiles: '30d',
                    format: winston.format.combine(
                        winston.format.timestamp(),
                        winston.format.printf(({ level, message, timestamp, stack, ...meta }) => {
                            let metaStr = Object.keys(meta).length ? JSON.stringify(meta, null, 2) : '';
                            let msg = stack || message;
                            if (typeof msg === 'object') msg = JSON.stringify(msg, null, 2);
                            return `[${timestamp}] ${level}: ${msg} ${metaStr}`;
                        })
                    ),
                }),
            ],
        });
    }

    log(message: string, meta?: Record<string, any>) {
        this.appLogger.info(message, meta);
    }

    warn(message: string, meta?: Record<string, any>) {
        this.appLogger.warn(message, meta);
    }

    error(message: string | Error, meta?: Record<string, any>) {
        if (message instanceof Error) {
            this.appLogger.error(message.stack ?? message.message, meta);
        } else {
            this.appLogger.error(message, meta);
        }
    }

    debug(message: string, meta?: Record<string, any>) {
        this.appLogger.debug(message, meta);
    }

    audit(action: string, details: Record<string, any>) {
        this.auditLogger.info({ action, ...details });
    }
}