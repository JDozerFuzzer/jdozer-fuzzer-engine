
const redis = require("redis");
const { randomUUID } = require("crypto");
const { exit } = require("process");
const { Logger } = require('@nestjs/common');

class JDozerFuzzerEngineProcessor {

    #log = new Logger('JDozerFuzzerEngineProcessor');
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
                throw new Error(`Fuzzer id: ${context.vars.testId} not found!`);
            }

            let fuzzer = JSON.parse(fuzzerRaw);
            for (let op of fuzzer.operationIds) {
                await this.#loadDmmCases(fuzzer.id, op);
            }

            this.#log.log(`Fuzzer ${fuzzer.name} loaded successfully!`);
            return;

        } catch (e) {
            this.#log.error("Error en beforeScenario:", e.message);
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
                        dmmCasesKeys[key] = reloaded;
                    }
                    this.#log.debug(`#updateDmmCases: ${key}: ${dmmCasesKeys[key].length}`);
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
            let keys = Object.keys(casesKeys);
            let selectedCaseKeyAndReduce = {};
            for (let key of keys) {
                if (casesKeys[key] != undefined) {
                    selectedCaseKeyAndReduce[key] = await this.#getDmmKeyAndReduce(casesKeys[key]);
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
            let dmmRaw = await this.#redis.get(qry);
            if (dmmRaw) {
                return JSON.parse(dmmRaw);
            }
            return undefined;
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
                this.#log.verbose(`#getDmmKeyAndReduce: selected key: ${arr[0]}`, `#getDmmKeyAndReduce: remaining keys: ${r.length}`);
                return { selectedCaseKey: c, rest: r };
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

            for (let a of attrs) {
                dmm[a] = await this.#getDmmKeysByType(fuzzerId, operationId, a)
            }
            this.#log.debug(`#loadDmmCases: payload: ${dmm.payload.length}`,
                `#loadDmmCases: headers: ${dmm.headers.length}`,
                `#loadDmmCases: query: ${dmm.query.length}`,
                `#loadDmmCases: path: ${dmm.path.length}`);
            await this.#redis.set('JDF:'.concat(fuzzerId).concat(':ENG:CASES:').concat(operationId), JSON.stringify(dmm));

        } catch (e) {
            console.error("Error en loadCases:", e);
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
            return await this.#redis.keys(fnd);
        } catch (e) {
            console.error("Error in #getDmmKeysByType:", e);
            throw e;
        }
    }

    /** */

    async beforeRequest(req, context, event, o) {

        try {

            let op = context.scenario.name.toString();

            let request = {
                uuidReq: req.uuid,
                operationId: op,
                url: req.url,
                params: {}
            };

            let dmmCases = this.#getCase(context.vars.testId, op);
            if (!dmmCases) {
                this.#log.warn(`No DMM cases for operation ${op} and fuzzer ${context.vars.testId}`);
                return;
            }

            let params = {};
            params.payload = dmmCases.payload;
            params.headers = dmmCases.headers;
            params.query = dmmCases.query;
            params.path = dmmCases.path;

            if (params.payload) {
                req.body = Buffer.from(params.payload.data, 'base64').toString('utf8');
                request.params.payloadId = params.payload.id;
                params.payload_valid = params.payload.valid;
            } else { params.payload = {} }

            if (params.headers) {
                req.headers = Buffer.from(params.headers.data, 'base64').toString('utf8');
                request.params.headersId = params.headers.id;
                params.headers_valid = params.headers.valid;
            } else { params.headers = {} }

            if (params.query) {
                req.query = Buffer.from(params.query.data, 'base64').toString('utf8');
                request.params.queryId = params.query.id;
                params.query_valid = params.query.valid;
            } else { params.query = {} }

            if (params.path) {
                let keys = Object.keys(params.path.data);

                for (let key of keys) {
                    req.url = req.url.replace(`{${key}}`, Buffer.from(params.path.data[key], 'base64').toString('utf8'));
                };

                if (keys.length === 0 && params.path.property) {
                    req.url = req.url.replace(`{${params.path.property}}`, '');
                }

                request.params.pathId = params.path.id;
                params.path_valid = params.path.valid;

            } else { params.path = {} }

            await this.#redis.set('JDF:'.concat(context.vars.testId).concat(':ENG:').concat(request.operationId).concat(':').concat(request.uuidReq).concat(':REQ'), JSON.stringify(request));


        } catch (e) {
            this.#log.error("Error en beforeRequest:", e.message);
            this.#log.error(e);
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

        } catch (e) {
            this.#log.error("Error en afterResponse:", e);
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

        await this.publishEvent('jdozer:fuzzer:broker', message);
        this.#log.log('Test completed!');

        return;

    }

    #redisConnect() {
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
            this.#log.debug(`[publishEvent] Published event: ${channel}:`, message);
        } catch (error) {
            this.#log.error('[publishEvent] Event exception:', error);
        }
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
    }
};

/**
let fuzzerId = 'e8166001-e566-4b9a-ae5f-b71e9fc76f91';
jDozerFuzzerEngineProcessor.beforeScenario({ vars: { testId: fuzzerId }, scenario: { name: 'updatePet' } }, {}).then(async () => {
    for (let i = 0; i < 5; i++) {
        let dmmCases = await jDozerFuzzerEngineProcessor.getCase(fuzzerId, 'updatePet');
        console.debug('Case Selected:', dmmCases);
    }
    exit(0);
}).catch((e) => {
    console.error('Error initializing scenario:', e);
});
*/