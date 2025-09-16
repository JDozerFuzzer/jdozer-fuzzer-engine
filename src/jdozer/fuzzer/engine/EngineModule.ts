/**
    # JDozerFuzzer - Microservicio de Discovery
    # Copyright (C) 2024 Cristián Saéz V.
    # Licencia: GNU AGPLv3 (ver LICENSE)
 */
import { Module } from '@nestjs/common';
import { JDozerFuzzerEngine } from './JDozerFuzzerEngine';
import { RedisService } from 'src/jdozer/fuzzer/engine/persistence/RedisService';
import { RedisEventsGateway } from './event/RedisEventGateway';
import { EngineScenarios } from './config/EngineScenarios';
import { EnginePhases } from './config/EnginePhases';

@Module({
  providers: [RedisService, JDozerFuzzerEngine, EngineScenarios, EnginePhases, RedisEventsGateway]
})
export class EngineModule { }
