import { Injectable, NestMiddleware } from '@nestjs/common';
import { Request, Response, NextFunction } from 'express';
import { LoggingService } from '../logging/logging.service';

@Injectable()
export class RequestLoggerMiddleware implements NestMiddleware {
  constructor(private readonly logger: LoggingService) {}

  use(req: Request, res: Response, next: NextFunction) {
    const { method, originalUrl, body, query, params } = req;

    this.logger.debug('Incoming request', {
      method,
      url: originalUrl,
      body,
      query,
      params,
    });

    const startTime = Date.now();
    res.on('finish', () => {
      const duration = Date.now() - startTime;
      this.logger.log('Request completed', {
        method,
        url: originalUrl,
        status: res.statusCode,
        duration: `${duration}ms`,
      });
    });

    next();
  }
}