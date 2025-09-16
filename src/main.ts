import { NestFactory } from '@nestjs/core';
import { ConfigModule } from '@nestjs/config';
import { EngineModule } from './jdozer/fuzzer/engine/EngineModule';

async function bootstrap() {

  try {
    await ConfigModule.forRoot({
      isGlobal: true,
      expandVariables: true
    });
  } catch (error) {
    console.error('Error setting up configuration:', error);
    process.exit(1);
  }

  const app = await NestFactory.create(EngineModule);

}
bootstrap();
