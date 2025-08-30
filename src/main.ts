import { NestFactory } from '@nestjs/core';
import { AppModule } from './app.module';
import { Logger } from '@nestjs/common';
import cookieParser from 'cookie-parser';
import { LoggingService } from './logging/logging.service';
import { AllExceptionsFilter } from './exception-filter';
import { RequestLoggerMiddleware } from './middleware/request-logger.middleware';

async function bootstrap() {
  const app = await NestFactory.create(AppModule);
  const logger = app.get(LoggingService);
  
  app.use(cookieParser());

  app.useGlobalFilters(new AllExceptionsFilter(logger));

  const port = process.env.PORT || 4000;
  await app.listen(port);
  logger.log(`NESTJS is running on port: ${port}`)
}

bootstrap();
