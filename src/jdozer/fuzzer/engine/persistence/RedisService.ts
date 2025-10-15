/**
    # JDozerFuzzer - Microservicio de Discovery
    # Copyright (C) 2024 Cristián Saéz V.
    # Licencia: GNU AGPLv3 (ver LICENSE)
 */
import { Injectable, OnModuleDestroy } from '@nestjs/common';
import { UUID } from 'crypto';
import * as Redis from 'ioredis';
import { KeyManager } from './KeyManager';

@Injectable()
export class RedisService implements OnModuleDestroy {

    private readonly keyManager: KeyManager = new KeyManager();
    private client: Redis.Redis;

    constructor() {
        this.client = new Redis.Redis({
            host: process.env.FUZZER_REDIS_HOST,
            port: +process.env.FUZZER_REDIS_PORT
        });
    }

    async set(key: string, value: any) {
        await this.client.set(key, JSON.stringify(value));
    }

    async get(key: string) {
        let data: any = JSON.parse(await this.client.get(key));
        return data;
    }

    async publish(channel: string, payload: any) {
        payload.data = Buffer.from(JSON.stringify(payload.data), 'binary').toString('base64');
        await this.client.publish(channel, JSON.stringify(payload));
    }

    async onModuleDestroy() {
        await this.client.quit();
    }

    async getFuzzer(fuzzerId: UUID) {
        return JSON.parse(await this.client.get(this.keyManager.forFuzz(fuzzerId)));
    }

    async getEng(fuzzerId: UUID) {
        return JSON.parse(await this.client.get(this.keyManager.forEngine(fuzzerId)));
    }

    async getKeys(keyPattern: string): Promise<string[]> {
        return await this.client.keys(keyPattern);
    }

    async getOperations(fuzzerId: UUID) {
        const fuzzer: any = await this.getFuzzer(fuzzerId);
        const operations: any[] = [];
        for (let id of fuzzer.operationIds) {
            const op: any = await this.get(this.keyManager.forOperation(id, fuzzer.id));
            operations.push(op);
        };
        return operations;
    }

    async getDummyCasesKeys(fuzzerId: UUID): Promise<string[]> {
        const keys: string[] = await this.getKeys(this.keyManager.getDMMAllKeys(fuzzerId));
        return keys;
    }

}