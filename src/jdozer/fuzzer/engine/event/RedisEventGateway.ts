/**
    # JDozerFuzzer - Microservicio de Discovery
    # Copyright (C) 2024 Cristián Saéz V.
    # Licencia: GNU AGPLv3 (ver LICENSE)
 */
import { Injectable, OnModuleInit, OnModuleDestroy, Logger, Inject, forwardRef } from '@nestjs/common';
import * as Redis from 'ioredis';
import { JDozerFuzzerEngine } from '../JDozerFuzzerEngine';
import { RedisService } from '../persistence/RedisService';
import { randomUUID, UUID } from 'crypto';

@Injectable()
export class RedisEventsGateway implements OnModuleDestroy {

    private readonly log = new Logger(RedisEventsGateway.name);
    private subscriber: Redis.Redis;

    private static readonly START_CHANNEL = process.env.FUZZER_VECTORS_CHANNEL || 'fuzzer:vectors';
    private static readonly ENTITY_TYPE = 'fuzzer-engine';
    private static readonly MY_CHANNEL = process.env.FUZZER_ENGINE_CHANNEL || 'fuzzer:engine';

    constructor(
        @Inject(forwardRef(() => JDozerFuzzerEngine))
        private readonly fuzzerEngine: JDozerFuzzerEngine,
        private readonly redisService: RedisService
    ) {
        this.log.verbose('[RedisEventsGateway] Initializing Redis Events Gateway...');
        this.log.verbose(`[RedisEventsGateway] Connecting to Redis server at: ${process.env.FUZZER_REDIS_HOST}:${process.env.FUZZER_REDIS_PORT}`);
        this.subscriber = new Redis.Redis({
            host: process.env.FUZZER_REDIS_HOST,
            port: +process.env.FUZZER_REDIS_PORT,
        });
        this.initialize();
    }

    async initialize() {

        this.log.log('[initialize] Initializing Redis Events Gateway...');
        this.log.log(`[initialize] Subscribing to Redis channel: ${RedisEventsGateway.START_CHANNEL}`);

        this.subscriber.on('error', (err) => {
            this.log.error(`[initialize] Redis subscriber error: ${err.message}`, err);
        });
        this.subscriber.on('ready', () => {
            this.log.verbose('[initialize] Redis subscriber is ready');
        });
        this.subscriber.on('connect', () => {
            this.log.verbose('[initialize] Redis subscriber connected');
        });
        this.subscriber.on('reconnecting', () => {
            this.log.verbose('[initialize] Redis subscriber is reconnecting');
        });
        this.subscriber.on('end', () => {
            this.log.verbose('[initialize] Redis subscriber connection ended');
        });
        this.subscriber.on('close', () => {
            this.log.verbose('[initialize] Redis subscriber connection closed');
        });
        this.subscriber.on('subscribe', (channel, count) => {
            this.log.verbose(`[initialize] Subscribed to channel: ${channel}, subscription count: ${count}`);
        });

        this.subscriber.on('message', async (channel, message) => {
            try {

                this.log.verbose(`[initialize] Message received on channel: ${channel}`);
                this.log.verbose(`[initialize] Message: ${message}`);

                if (RedisEventsGateway.START_CHANNEL !== channel) {
                    this.log.warn(`[initialize] Ignoring message from channel: ${channel}`);
                    return;
                }

                const event = JSON.parse(message);
                await this.router(event);

            } catch (err) {
                this.log.error(`[initialize] Error parsing message: ${err.message}`, err);
            }
        });

        await this.subscriber.subscribe(RedisEventsGateway.START_CHANNEL);
        this.log.verbose(`[initialize] Redis Events Gateway initialized and subscribed to channel: ${RedisEventsGateway.START_CHANNEL}`);
    }

    private async router(event: any) {

        if (!event || !event.headers.entityType || !event.headers.eventType || !event.payload || !event.headers.entityId) {
            this.log.error('[router] Invalid event data received:', event);
            return;
        }

        if ('fuzzer-vectors' === event.headers.entityType && event.headers.eventType === 'builder-successful') {
            this.log.verbose(`[router] Processing event: entityType[${event.headers.entityType}], eventType[${event.headers.eventType}]`);

            try {
                await this.fuzzerEngine.start(event.payload.fuzzerId as UUID);
                this.log.log(`[router] Engine started for fuzzerId: ${event.payload.fuzzerId}`);
                return;
            } catch (e) {
                this.log.error(`[router] Error starting engine: ${e.message}`, e);
                await this.publish(event.payload.fuzzerId as UUID, 'error', {
                    fuzzerId: event.payload.fuzzerId,
                    message: e.message,
                    details: e.details,
                    action: 'retry'
                });
            }
        } else {
            this.log.verbose(event);
            this.log.warn(`[routeEvent] Unsupported event type: entityType[${event.headers.entityType}], eventType[${event.headers.eventType}]`);
            return;
        }
    }

    async publish(entityId: UUID, eventType: string, payload: any) {
        try {
            const event = {
                headers: {
                    id: randomUUID(),
                    timestamp: new Date().getTime(),
                    version: '1.0.0',
                    entityId: entityId,
                    entityType: RedisEventsGateway.ENTITY_TYPE,
                    eventType: eventType
                },
                payload: payload
            };
            await this.redisService.publish(RedisEventsGateway.MY_CHANNEL, event);
        } catch (e) {
            this.log.error(`[publish] Error publishing event: ${e.message}`, e);
            throw e;
        }

    }

    async onModuleDestroy() {
        await this.subscriber.quit();
    }
}
