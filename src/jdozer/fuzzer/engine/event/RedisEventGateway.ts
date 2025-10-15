/**
    # JDozerFuzzer - Microservicio de Discovery
    # Copyright (C) 2024 Cristián Saéz V.
    # Licencia: GNU AGPLv3 (ver LICENSE)
 */
import { Injectable, OnModuleInit, OnModuleDestroy, Logger } from '@nestjs/common';
import * as Redis from 'ioredis';
import { JDozerFuzzerEngine } from '../JDozerFuzzerEngine';
import { RedisService } from '../persistence/RedisService';
import { randomUUID, UUID } from 'crypto';

@Injectable()
export class RedisEventsGateway implements OnModuleDestroy {

    private readonly log = new Logger(RedisEventsGateway.name);
    private subscriber: Redis.Redis;

    private static readonly CHANNEL = 'jdozer:fuzzer:broker';
    private static readonly ENTITY = 'fuzzer-engine';

    constructor(
        private readonly fuzzerEngine: JDozerFuzzerEngine,
        private readonly redisService: RedisService
    ) {
        this.log.verbose('[RedisEventsGateway] Initializing Redis Events Gateway...');
        this.log.verbose(`[RedisEventsGateway] Connecting to Redis server at: ${process.env.REDIS_HOST}:${process.env.REDIS_PORT}`);
        this.subscriber = new Redis.Redis({
            host: process.env.FUZZER_REDIS_HOST,
            port: +process.env.FUZZER_REDIS_PORT,
        });
        this.initialize();
    }

    async initialize() {

        this.log.log('[initialize] Initializing Redis Events Gateway...');
        this.log.log(`[initialize] Subscribing to Redis channel: ${RedisEventsGateway.CHANNEL}`);

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

                if (RedisEventsGateway.CHANNEL !== channel) {
                    this.log.debug(`[initialize] Ignoring message from channel: ${channel}`);
                    return;
                }

                const event = JSON.parse(message);
                await this.router(event);

            } catch (err) {
                this.log.error(`[initialize] Error parsing message: ${err.message}`, err);
            }
        });

        await this.subscriber.subscribe(RedisEventsGateway.CHANNEL);
        this.log.verbose(`[initialize] Redis Events Gateway initialized and subscribed to channel: ${RedisEventsGateway.CHANNEL}`);
    }

    private async router(event: any) {

        if (!event || !event.entityType || !event.eventType || !event.data || !event.entityId) {
            this.log.error('[router] Invalid event data received:', event);
            return;
        }

        if ('fuzzer-vectors' === event.entityType && event.eventType === 'load-success') {
            this.log.verbose(`[router] Processing event: entityType[${event.entityType}], eventType[${event.eventType}]`);

            try {
                const fuzzer: any = JSON.parse(Buffer.from(event.data, 'base64').toString('binary'));
                await this.fuzzerEngine.start(event.entityId as UUID);
                const eventData = {
                    fuzzerId: fuzzer.fuzzerId,
                    status: 'attack-started',
                    timestamp: new Date().getTime()
                };
                this.publish(RedisEventsGateway.CHANNEL, event.traceId, fuzzer.fuzzerId, 'attack-started', eventData);
                this.log.debug(`[router] Engine started for fuzzerId: ${fuzzer.fuzzerId}`);
                return;
            } catch (e) {
                this.log.error(`[router] Error starting engine: ${e.message}`, e);
                this.publish(RedisEventsGateway.CHANNEL, event.traceId, event.entityId, 'attack-failed', {
                    status: 'attack-failed',
                    timestamp: new Date().getTime(),
                    data: event.data
                });
            }
        } else {
            this.log.verbose(`[routeEvent] Unsupported event type: entityType[${event.entityType}], eventType[${event.eventType}]`);
            return;
        }
    }

    async publish(channel: string, traceId: UUID, entityId: UUID, eventType: string, payload: any) {
        try {
            const event = {
                id: randomUUID(),
                traceId: traceId,
                timestamp: new Date().getTime(),
                entityId: entityId,
                entityType: RedisEventsGateway.ENTITY,
                eventType: eventType,
                data: payload
            };

            await this.redisService.publish(channel, event);
        } catch (e) {
            this.log.error(`[publish] Error publishing event: ${e.message}`, e);
            throw e;
        }

    }

    async onModuleDestroy() {
        await this.subscriber.quit();
    }
}
