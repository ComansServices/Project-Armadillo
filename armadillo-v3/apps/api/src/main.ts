import 'reflect-metadata';
import { NestFactory } from '@nestjs/core';
import { Module, Controller, Get } from '@nestjs/common';

@Controller('/health')
class HealthController {
  @Get()
  health() {
    return { ok: true, service: 'armadillo-api' };
  }
}

@Module({ controllers: [HealthController] })
class AppModule {}

async function bootstrap() {
  const app = await NestFactory.create(AppModule);
  await app.listen(4000);
  console.log('API listening on http://localhost:4000');
}

bootstrap();
