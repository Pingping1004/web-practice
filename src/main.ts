import { NestFactory } from '@nestjs/core';
import { AppModule } from './app.module';
import { Logger } from '@nestjs/common';
import cookieParser from 'cookie-parser';

async function bootstrap() {
  const logger = new Logger('Bootstrap');
  const app = await NestFactory.create(AppModule);
  
  app.use(cookieParser());

  const port = process.env.PORT || 4000;
  await app.listen(port);
  logger.log(`NESTJS is running on port: ${port}`)
}

bootstrap();
