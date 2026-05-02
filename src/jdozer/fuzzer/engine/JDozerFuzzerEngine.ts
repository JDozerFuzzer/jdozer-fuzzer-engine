/**
    # JDozerFuzzer - Microservicio de Discovery
    # Copyright (C) 2024 Cristián Saéz V.
    # Licencia: GNU AGPLv3 (ver LICENSE)
 */
import { Injectable, Logger, Inject, forwardRef } from '@nestjs/common';
import { spawn } from 'child_process';
import { randomUUID, UUID } from 'crypto';

import * as YAML from 'yaml';
import * as fs from 'fs';
import { EngineException } from './EngineException';
import { RedisService } from './persistence/RedisService';
import { EngineScenarios } from './config/EngineScenarios';
import { KeyManager } from './persistence/KeyManager';
import { EnginePhases } from './config/EnginePhases';
import { RedisEventsGateway } from './event/RedisEventGateway';
import { CasesCount } from './event/CasesCount';

@Injectable()
export class JDozerFuzzerEngine {

  private readonly log = new Logger(JDozerFuzzerEngine.name);
  private readonly keyManger: KeyManager = new KeyManager();

  private fuzzer: any;

  constructor(
    private readonly redisService: RedisService,
    private readonly engineScenarios: EngineScenarios,
    private readonly enginePhases: EnginePhases,
    @Inject(forwardRef(() => RedisEventsGateway))
    private readonly eventGateway: RedisEventsGateway
  ) { }

  async start(fuzzerId: UUID, timeLength: number = 1): Promise<void> {
    try {

      this.fuzzer = await this.redisService.getFuzzer(fuzzerId);
      const operations: any[] = await this.getOperations(this.fuzzer.id);
      const cases: string[] = await this.getCasesKeys(this.fuzzer.id);

      await (new CasesCount(this.eventGateway)).send(fuzzerId, cases);

      let engCfg = await this.redisService.getEng(this.fuzzer.id);

      engCfg.scenarios = await this.engineScenarios.build(operations, cases);
      engCfg.config.phases = this.enginePhases.build(engCfg.scenarios, cases.length, operations.length, timeLength);

      engCfg.config.ensure = ['onError'];

      engCfg.config.processor = this.targetProcessor();
      engCfg.config.plugins = this.targetPlugins(this.fuzzer);
      engCfg.before = { flow: [{ function: 'before' }] };

      this.redisService.set(this.keyManger.forEngine(this.fuzzer.id), engCfg);

      let engCfgYml = YAML.stringify(engCfg);
      this.exec(engCfgYml, this.fuzzer.id);

      this.engineStartedEvent(engCfg, cases.length, this.fuzzer.id);

      this.log.log('Fuzzer Engine started!');

      return;

    } catch (e) {
      throw new EngineException({
        message: `Oops! Fuzzer Engine failed to start!, fuzzerId: ${fuzzerId}`,
        details: `${e.message}`
      });
    }
  }

  private targetProcessor() {
    return `${process.cwd()}/src/processor/JDozerFuzzerEngineProcessor.cjs`;
  }

  private targetPlugins(fuzzer: any) {

    const plugins = {};
    plugins['publish-metrics'] = [];
    // plugins['publish-metrics'].push(this.getPrometheusMetrics(fuzzer.name, fuzzer.version));

    return plugins;
  }

  private getPrometheusMetrics(fuzzName: string, fuzzVersion: string): any {
    return {
      type: 'prometheus',
      prefix: 'jdozzerfuzzer',
      pushgateway: `http://${process.env.FUZZER_PUSHGATEWAY_HOST}:${process.env.FUZZER_PUSHGATEWAY_PORT}`,
      tags: [`JDozerFuzzer:${fuzzName.concat('_').concat(fuzzVersion).replaceAll(' ', '_')}`]
    };
  }

  private async exec(cfg: string, prefix: string, options: string[] = []): Promise<void> {

    const fileName = `${prefix}-engine-cfg.yml`;
    const summaryFile = `${prefix}-summary.json`
    const pathFile = `/tmp/${fileName}`;
    fs.writeFileSync(pathFile, cfg);

    return new Promise((resolve, reject) => {

      const workingDirectory = __dirname;

      const engineProcess = spawn('artillery', ['run', `--quiet`, `--output`, `/tmp/${summaryFile}`, ...options, pathFile.toString()], {
        detached: true,
        cwd: workingDirectory,
        stdio: ['pipe', 'inherit', 'inherit']
      });

      engineProcess.on('close', async (code) => {
        if (code !== 0) {
          reject(new Error(`Engine process exited with code ${code}`));
        } else {
          await this.engineStoppedEvent(this.fuzzer.id);
          console.info(`Engine process with id ${engineProcess.pid} exited successfully!`);
          resolve();
        }
      });

      engineProcess.on('error', (err) => {
        console.error(`Engine process encountered an error: ${err}`);
        reject(err);
      });

      console.info(`Engine process started with id ${engineProcess.pid}`);
      engineProcess.unref();

    });
  }

  private async getOperations(fuzzerId: UUID): Promise<any> {
    try {
      return await this.redisService.getOperations(fuzzerId);
    } catch (e) {
      throw new EngineException({ message: `Oops! Failed to get Operations!`, details: e.message });
    }
  }

  private async getCasesKeys(fuzzerId: UUID): Promise<string[]> {
    try {
      return await this.redisService.getDummyCasesKeys(fuzzerId);
    } catch (e) {
      throw new EngineException({ message: `Oops! Failed to get Cases Keys!`, details: e.message });
    }
  }

  private async engineStartedEvent(config: any, cases: number, fuzzerId: UUID) {
    const payload = {
      fuzzerId: fuzzerId,
      phases: {},
      scenarios: {},
      totalCases: cases
    };
    for (let phase of config.config.phases) {
      payload.phases[phase.name] = {
        duration: phase.duration,
        arrivalRate: phase.arrivalRate,
        maxUsers: phase.maxVusers,
        rampTo: phase.rampTo
      };
    }
    for (let scenario of config.scenarios) {
      payload.scenarios[scenario.name] = {
        weight: scenario.weight
      };
    }
    await this.eventGateway.publish(fuzzerId, 'engine-started', payload);
  }

  private async engineStoppedEvent(fuzzerId: UUID) {
    await this.eventGateway.publish(fuzzerId, 'engine-stopped', {
      fuzzerId: fuzzerId
    });
  }

  private readonly _MSG_NOTFOUND: string = 'Fuzzer not found or not owned by the current user!';
}
