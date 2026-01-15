
const redis = require("redis");
const { randomUUID } = require("crypto");
const { exit } = require("process");
const { Logger } = require('@nestjs/common');

class JDozerFuzzerEngineProcessor {

    #log = new Logger('JDozerFuzzerEngineProcessor', {
        level: process.env.FUZZER_LOG_LEVEL
    });
    #redis;

    constructor() {
        this.#log.log('JDozerFuzzerEngineProcessor initialized');
        this.#redisConnect();
    }

    /**
     * 
     * @param {*} context
     * @param {*} event
     * @returns 
     */
    async prepareCases(context, event) {
        try {

            let fuzzerRaw = await this.#redis.get('JDF:'.concat(context.vars.testId));
            if (!fuzzerRaw) {
                let err = `Fuzzer id: ${context.vars.testId} not found!`;
                this.#log.error(err);
                throw new Error(err);
            }

            let fuzzer = JSON.parse(fuzzerRaw);

            this.runtimeEvents({ fuzzerId: context.vars.testId }, 'prepare-cases');

            for (let op of fuzzer.operationIds) {
                await this.#loadDmmCases(fuzzer.id, op);
                this.runtimeEvents({ fuzzerId: context.vars.testId, operationId: op }, 'cases-loaded');
            }

            this.#log.log(`Fuzzer ${fuzzer.name} loaded successfully!`);
            return;

        } catch (e) {
            this.#log.error("Error en prepareCases:", e.message);
            throw e;
        }
    }

    /**
     * 
     * @param {import("crypto").UUID} fuzzerId 
     * @param {string} operationId 
     * @returns dmmCase: { payload: string, headers: string, query: string, path: string } | { }
     */
    async #getCase(fuzzerId, operationId) {
        try {
            let casesKeys = await this.#getDmmCases(fuzzerId, operationId);
            if (!casesKeys) {
                this.#log.warn(`#getCase: No DMM cases for operation ${operationId} and fuzzer ${fuzzerId}`);
                return undefined;
            }
            let selectedCaseKeyAndReduce = await this.#getCasesKeys(casesKeys);
            await this.#updateDmmCases(selectedCaseKeyAndReduce, operationId, fuzzerId);

            let dmmCase = {};
            for (let key in selectedCaseKeyAndReduce) {
                if (selectedCaseKeyAndReduce[key].selectedCaseKey != undefined) {
                    dmmCase[key] = selectedCaseKeyAndReduce[key].selectedCaseKey;
                }
            }
            return dmmCase;

        } catch (e) {
            this.#log.error("Error in getCase:", e);
            throw e;
        }
    }

    /**
     * 
     * @param {selectedCaseKeyAndReduce} selectedCaseKeyAndReduce 
     * @param {string} operationId 
     * @param {import("crypto").UUID} fuzzerId 
     * @returns Promise<void>
     */
    async #updateDmmCases(selectedCaseKeyAndReduce, operationId, fuzzerId) {
        try {
            let keys = Object.keys(selectedCaseKeyAndReduce);
            let dmmCasesKeys = {};
            for (let key of keys) {
                if (selectedCaseKeyAndReduce[key].rest != undefined) {
                    dmmCasesKeys[key] = selectedCaseKeyAndReduce[key].rest;
                    if (dmmCasesKeys[key].length === 0) {
                        let reloaded = await this.#getDmmKeysByType(fuzzerId, operationId, key);
                        dmmCasesKeys[key] = (reloaded.length === 0) ? undefined : reloaded;
                        this.#log.verbose(`#updateDmmCases: Reloaded DMM cases keys for type ${key}: ${dmmCasesKeys[key].length} total`);
                    } else {
                        this.#log.verbose(`#updateDmmCases: Remaining DMM cases keys for type ${key}: ${dmmCasesKeys[key].length} remaining`);
                    }
                } else {
                    this.#log.verbose(`#updateDmmCases: No remaining DMM cases keys for type ${key}`);
                }
            }
            await this.#redis.set('JDF:'.concat(fuzzerId).concat(':ENG:CASES:').concat(operationId), JSON.stringify(dmmCasesKeys));
            return;
        } catch (e) {
            this.#log.error("Error in #updateDmmCases:", e);
            throw e;
        }
    }

    /**
     * 
     * @param casesKeys: { payload: string[], headers: string[], query: string[], path: string[] } casesKeys 
     * @returns selectedCaseKeyAndReduce: { payload: { selectedCaseKey: string, rest: string[] }, headers: { selectedCaseKey: string, rest: string[] }, query: { selectedCaseKey: string, rest: string[] }, path: { selectedCaseKey: string, rest: string[] } }
     */
    async #getCasesKeys(casesKeys) {
        try {
            this.#log.verbose(`#getCasesKeys: ${Object.keys(casesKeys)}`);
            let keys = Object.keys(casesKeys);
            let selectedCaseKeyAndReduce = {};
            for (let key of keys) {
                if (casesKeys[key] != undefined) {
                    this.#log.verbose(`#getCasesKeys: ${key}:${casesKeys[key].length}`);
                    selectedCaseKeyAndReduce[key] = await this.#getDmmKeyAndReduce(casesKeys[key]);
                    this.#log.verbose(`#getCasesKeys: Reduce: ${key}:${selectedCaseKeyAndReduce[key].rest.length}`);
                }
            }
            return selectedCaseKeyAndReduce;
        } catch (e) {
            this.#log.error("Error in #getCasesKeys:", e);
            throw e;
        }
    }

    /**
     * 
     * @param {import("crypto").UUID} fuzzerId 
     * @param {string} operationId 
     * @returns casesKeys: { payload: string[], headers: string[], query: string[], path: string[] } | undefined
     */
    async #getDmmCases(fuzzerId, operationId) {
        try {
            let qry = 'JDF:'.concat(fuzzerId).concat(':ENG:CASES:').concat(operationId);
            this.#log.verbose(`#getDmmCases: Querying DMM cases with key: ${qry}`);
            let cases = JSON.parse(await this.#redis.get(qry));
            return (Object.keys(cases).length > 0) ? cases : undefined;
        } catch (e) {
            console.error("Error in #getDmmCases:", e);
            throw e;
        }
    }

    /**
     * 
     * @param {string[]} arr 
     * @returns keyAndReduce: { selectedCaseKey: string, rest: string[] } | {}
     */
    async #getDmmKeyAndReduce(arr) {
        try {
            if (arr != undefined && arr.length > 0) {
                let c = await this.#redis.get(arr[0]);
                let r = arr.slice(1);
                let keyAndReduce = { selectedCaseKey: c, rest: r };
                this.#log.verbose(`#getDmmKeyAndReduce: keyAndReduce: ${keyAndReduce.rest.length}`, `selectedCaseKey: ${keyAndReduce.selectedCaseKey}`);
                return keyAndReduce;
            }
            return {};
        } catch (e) {
            this.#log.error("Error in #getDmmKeyAndReduce:", e);
            throw e;
        }
    }

    /**
     * 
     * @param {import("crypto").UUID} fuzzerId 
     * @param {string} operationId 
     * @returns Promise<void>
     */
    async #loadDmmCases(fuzzerId, operationId) {
        try {

            let attrs = ['headers', 'payload', 'query', 'path'];
            let dmm = {};

            let keys;
            for (let a of attrs) {
                keys = await this.#getDmmKeysByType(fuzzerId, operationId, a);
                if (keys.length > 0)
                    dmm[a] = keys;
            }

            this.#log.debug(`#loadDmmCases from ${operationId}`, `keys: ${Object.keys(dmm)}`);
            await this.#redis.set('JDF:'.concat(fuzzerId).concat(':ENG:CASES:').concat(operationId), JSON.stringify(dmm));

        } catch (e) {
            console.error(`#loadDmmCases: ${e.message}`);
            throw e;
        }
    }

    /**
     * 
     * @param {import("crypto").UUID} fuzzerId 
     * @param {string} operationId 
     * @param {string} type 
     * @returns string[] Lista de keys DMM
     */
    async #getDmmKeysByType(fuzzerId, operationId, type) {
        try {
            let fnd = 'JDF:'.concat(fuzzerId).concat(':DMM:').concat(operationId).concat(':').concat(type).concat(':*');
            this.#log.verbose(`#getDmmKeysByType: Finding DMM keys with pattern: ${fnd}`);
            return await this.#redis.keys(fnd);
        } catch (e) {
            let err = `Error in #getDmmKeysByType for type ${type}: ${e.message}`;
            this.#log.error(err);
            throw new Error(err);
        }
    }

    /**
     * 
     * @param {*} req 
     * @param {*} context 
     * @param {*} event 
     * @param {*} o 
     * @returns 
     */
    async beforeRequest(req, context, event, o) {

        try {

            let op = context.scenario.name.toString();
            this.#log.verbose(`Request for operation: ${op}`);

            let request = {
                uuidReq: req.uuid,
                operationId: op,
                url: req.url,
                params: {}
            };

            let dmmCases = await this.#getCase(context.vars.testId, op);
            if (!dmmCases) {
                this.#log.warn(`No DMM cases for operation ${op} and fuzzer ${context.vars.testId}`);
                return;
            } else {
                this.#log.debug(`DMM cases for operation ${op} found`);
            }

            this.#log.verbose(`beforeRequest: dmmCases: ${Object.keys(dmmCases)}`);

            let params = {};
            params.payload = dmmCases.payload;
            params.headers = dmmCases.headers;
            params.query = dmmCases.query;
            params.path = dmmCases.path;

            if (params.payload) {
                let payload = JSON.parse(params.payload);
                req.body = Buffer.from(payload.data, 'base64').toString('utf8');
                request.params.payloadId = payload.id;
                params.payload_valid = payload.valid;
            } else { params.payload = {} }

            if (params.headers) {
                let headers = JSON.parse(params.headers);
                req.headers = Buffer.from(headers.data, 'base64').toString('utf8');
                request.params.headersId = headers.id;
                params.headers_valid = headers.valid;
            } else { params.headers = {} }

            if (params.query) {
                let query = JSON.parse(params.query);
                req.query = Buffer.from(query.data, 'base64').toString('utf8');
                request.params.queryId = query.id;
                params.query_valid = query.valid;
            } else { params.query = {} }

            if (params.path) {
                let path = JSON.parse(params.path);
                let dataRaw = Buffer.from(path.data, 'base64').toString('utf8');
                let data = JSON.parse(dataRaw);
                let keys = Object.keys(data);

                for (let key of keys) {
                    req.url = req.url.replace(`{${key}}`, data[key]);
                };

                /**
                 * @todo: Tengo dudas sobre este codigo.
                 */
                if (keys.length === 0 && params.path.property) {
                    req.url = req.url.replace(`{${path.property}}`, '');
                }

                request.params.pathId = path.id;
                params.path_valid = path.valid;

            } else { params.path = {} }

            this.runtimeEvents({ fuzzerId: context.vars.testId, operationId: request.operationId, uuidReq: request.uuidReq }, 'request-created');

            await this.#redis.set('JDF:'.concat(context.vars.testId).concat(':ENG:').concat(request.operationId).concat(':').concat(request.uuidReq).concat(':REQ'), JSON.stringify(request));


        } catch (e) {
            this.#log.error("Error en beforeRequest:", e);
        }
    }

    async afterResponse(req, res, context, event) {

        try {
            let response = {
                uuidRes: res.uuid,
                uuidReq: req.uuid,
                payload: Buffer.from(res.body).toString('base64'),
                headers: res.headers,
                ip: res.ip,
                complete: res.complete,
                statusCode: res.statusCode,
                statusMessage: res.statusMessage,
                servername: res.servername,
                url: res.url,
                aborted: res.aborted,
                timings: {
                    start: res.timings.start,
                    socket: res.timings.socket,
                    lookup: res.timings.lookup,
                    connect: res.timings.connect,
                    secureConnect: res.timings.secureConnect,
                    secureConnect: res.timings.secureConnect,
                    upload: res.timings.upload,
                    response: res.timings.response,
                    end: res.timings.end,
                    phases: {
                        wait: res.timings.phases.wait,
                        dns: res.timings.phases.dns,
                        tcp: res.timings.phases.tcp,
                        tls: res.timings.phases.tls,
                        request: res.timings.phases.request,
                        firstByte: res.timings.phases.firstByte,
                        download: res.timings.phases.download,
                        total: res.timings.phases.total
                    }
                },
                time: new Date().getTime()
            };

            let reqKey = (await this.#redis.keys('JDF:*:ENG:*:'.concat(req.uuid).concat(':REQ')))[0];
            await this.#redis.set(reqKey.replace(':REQ', ':RES'), JSON.stringify(response));

            const reqBef = JSON.parse(await this.#redis.get(reqKey));
            let reqAgr = Object.assign({}, req);
            reqAgr.params = reqBef.params;
            reqAgr.operationId = reqBef.operationId;
            reqAgr.agent = undefined;
            await this.#redis.set(reqKey, JSON.stringify(reqAgr));

            this.runtimeEvents({
                fuzzerId: context.vars.testId,
                operationId: req.operationId,
                uuidReq: req.uuid,
                statusCode: res.statusCode,
                statusMessage: res.statusMessage
            }, 'response-received');

        } catch (e) {
            this.#log.error("Error en afterResponse:", e);
            this.#log.error(`Values: requestId: ${req.uuid}`);
        }

    }

    async afterTest(context) {

        const message = {
            id: randomUUID(),
            timestamp: new Date().getMilliseconds(),
            traceId: context.vars.testId,
            entityId: context.vars.testId,
            entityType: 'fuzzer-engine',
            eventType: 'attack-completed',
            data: {}
        };

        this.runtimeEvents({ fuzzerId: context.vars.testId }, 'attack-completed');

        await this.publishEvent('jdozer:fuzzer:broker', message);
        this.#log.log('Test completed!');

        return;

    }

    async #redisConnect() {
        if (!this.#redis) {
            this.#redis = redis.createClient({
                url: `redis://${process.env.FUZZER_REDIS_HOST}:${process.env.FUZZER_REDIS_PORT}`
            });
            this.#redis.on("error", (err) => this.#log.error("Redis connect error: ", err));
            this.#redis.connect()
                .then(() => this.#log.log(`Redis connected successfully!`, `PID: ${process.pid}`))
                .catch(this.#log.error);
        }
    }

    async publishEvent(channel, message) {

        if (!this.#redis) {
            this.#log.error('[publishEvent] Redis no connected!');
            return;
        }

        try {
            message.data = btoa(JSON.stringify(message.data));
            await this.#redis.publish(channel, JSON.stringify(message));
            // this.#log.verbose(`[publishEvent] Published event: ${channel}:`, message);
        } catch (error) {
            this.#log.error('[publishEvent] Event exception:', error);
        }
    }

    async runtimeEvents(payload, eventType) {
        return this.publishEvent(`jdozer:fuzzer:engine`, {
            id: randomUUID(),
            fuzzerId: payload.fuzzerId,
            eventType: eventType,
            entityType: 'engine',
            timestamp: Date.now(),
            payload: payload
        });
    }

};

const jDozerFuzzerEngineProcessor = new JDozerFuzzerEngineProcessor();

module.exports = {

    async before(context, event) {
        await jDozerFuzzerEngineProcessor.prepareCases(context, event);
    },

    async beforeRequest(req, context, event) {
        await jDozerFuzzerEngineProcessor.beforeRequest(req, context, event);
    },

    async afterResponse(req, res, context, event) {
        await jDozerFuzzerEngineProcessor.afterResponse(req, res, context, event);
    },

    async afterTest(context) {
        await jDozerFuzzerEngineProcessor.afterTest(context);
    },
    jDozerFuzzerEngineProcessor
};
