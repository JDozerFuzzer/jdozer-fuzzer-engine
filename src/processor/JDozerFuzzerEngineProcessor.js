const redis = require("redis");
const Ajv = require("ajv");
const addFormats = require('ajv-formats');
const { randomUUID } = require("crypto");

class JDozerFuzzerEngineProcessor {

    #redis;

    constructor() {
        this.#redisConnect();
    }

    async beforeScenario(context, event) {
        try {

            if (!context.vars.testId || !context.scenario.name) {
                throw new Error("Test or Operation not defined!");
            }

        } catch (e) {
            console.error("Error en beforeScenario:", e);
        }
    }

    async beforeRequest(req, context, event, o) {

        try {

            let op = context.scenario.name.toString();
            let fnd = 'JDF:'.concat(context.vars.testId).concat(':DMM:').concat(op).concat(':*');
            let dIdx = await this.#redis.keys(fnd);

            let pay = dIdx.filter(d => d.search(':payload:') > 2);
            let hea = dIdx.filter(d => d.search(':headers:') > 2);
            let qry = dIdx.filter(d => d.search(':query:') > 2);
            let pat = dIdx.filter(d => d.search(':path:') > 2);

            let fnIdx = (array) => {
                let l = (array.length == 0 ? -1 : array.length);
                return Math.floor(Math.random() * l);
            };

            let payIdx = fnIdx(pay);
            let heaIdx = fnIdx(hea);
            let qryIdx = fnIdx(qry);
            let patIdx = fnIdx(pat);

            let proms = [];
            proms.push(this.#redis.get(pay[payIdx]));
            proms.push(this.#redis.get(hea[heaIdx]));
            proms.push(this.#redis.get(qry[qryIdx]));
            proms.push(this.#redis.get(pat[patIdx]));

            let ps = await Promise.allSettled(proms);
            let params = {};
            params.payload = (ps[0].value ? JSON.parse(ps[0].value) : undefined);
            params.headers = (ps[1].value ? JSON.parse(ps[1].value) : undefined);
            params.query = (ps[2].value ? JSON.parse(ps[2].value) : undefined);
            params.path = (ps[3].value ? JSON.parse(ps[3].value) : undefined);

            let request = {
                uuidReq: req.uuid,
                operationId: op,
                url: req.url,
                params: {}
            };

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
            console.error("Error en beforeRequest:", e.message);
            console.error(e);
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
            console.error("Error en afterResponse:", e);
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
        console.info('Test completed!');

        return;


        try {

            console.debug('context_vars:', context);
            const reqKeys = await this.#redis.keys('JDF:'.concat(context.vars.testId).concat('*:RE?'));

            for (let reqKey of reqKeys) {
                let req = JSON.parese(await this.#redis.get(reqKey));
                const params = Object.keys(req.params);
                for (let param of params) {
                    let paramType = this.#getParamType(param);
                    let key = 'JDF:FKE:'.concat(context.vars.testId).concat(':').concat(req.operationId).concat(':').concat(paramType).concat(':').concat(req.params[param]);
                    let fke = JSON.parse(await this.#redis.get(key));
                    req.params[paramType] = fke;
                };
                this.#redis.set(reqKey, JSON.stringify(req));
            }

            const event = {
                entityType: "engine",
                eventType: "attack-completed",
                data: {
                    fuzzerId: context.vars.testId,
                    owner: context.vars.owner,
                }
            };

            await this.publishEvent('jdozer:fuzzer:broker', event);
            console.info('Test completed!');

            return;

        } catch (e) {
            console.error("Error en afterTest:", e);
        }

        let fuzzer = JSON.parse(await this.#redis.get('JDF:ID:'.concat(context.vars.testId)));
        for (let opId of fuzzer.operationIds) {
            let op = JSON.parse(await this.#redis.get('JDF:OP:'.concat(opId)));
            let reqKeys = await this.#redis.keys('JDF:REQ:'.concat(context.vars.testId).concat(':').concat(op.name).concat(':*'));
            for (let reqKey of reqKeys) {

                let req = JSON.parse(await this.#redis.get(reqKey));
                let res = JSON.parse(await this.#redis.get('JDF:RES:'.concat(context.vars.testId).concat(':').concat(op.name).concat(':').concat(req.uuidReq)));

                if (!res) {
                    console.error('Response not found!', reqKey);
                    continue;
                }

                let resSchema = this.#getSchemaFromStatusCode(res.statusCode, op.res);

                let ajv = new Ajv();
                ajv.addVocabulary(['xml', 'example']);
                addFormats(ajv);
                let resSchValid = this.#schemaValidator(resSchema, res.payload, ajv);

                let pay = (req.payloadId ? JSON.parse(await this.#redis.get(op.name.concat(':payload:').concat(req.payloadId))) : undefined);
                let hea = (req.headersId ? JSON.parse(await this.#redis.get(op.name.concat(':headers:').concat(req.headersId))) : undefined);
                let qry = (req.queryId ? JSON.parse(await this.#redis.get(op.name.concat(':query:').concat(req.queryId))) : undefined);
                let pat = (req.pathId ? JSON.parse(await this.#redis.get(op.name.concat(':path:').concat(req.pathId))) : undefined);

                let data = [
                    fuzzer.id,
                    req.uuidReq,
                    op.name,
                    op.method,
                    req.url,
                    (hea ? Buffer.from(hea.data, 'base64').toString('utf8') : null),
                    (hea ? hea.valid : null),
                    (hea ? hea.message : null),
                    (hea ? (hea.property ? hea.property : null) : null),

                    (pay ? Buffer.from(pay.data, 'base64').toString('utf8') : null),
                    (pay ? pay.valid : null),
                    (pay ? pay.message : null),
                    (pay ? (pay.property ? pay.property : null) : null),

                    (qry ? Buffer.from(qry.data, 'base64').toString('utf8') : null),
                    (qry ? qry.valid : null),
                    (qry ? qry.message : null),
                    (qry ? (qry.property ? qry.property : null) : null),

                    (pat ? Buffer.from(pat.data, 'base64').toString('utf8') : null),
                    (pat ? pat.valid : null),
                    (pat ? pat.message : null),
                    (pat ? (pat.property ? pat.property : null) : null),

                    (res.uuidRes ? res.uuidRes : null),
                    res.statusCode,
                    JSON.stringify(res.headers),
                    res.payload,
                    resSchValid.valid,
                    (!resSchValid.valid ? JSON.stringify(resSchValid.errors) : null),
                    new Date(res.time).toISOString().slice(0, 19).replace('T', ' ')
                ];

            }
        }

    }

    #getParamType(param) {
        switch (param) {
            case 'payloadId':
                return 'payload';
            case 'headersId':
                return 'headers';
            case 'queryId':
                return 'query';
            case 'pathId':
                return 'path';
            default:
                console.error('Error: unknown parameter type', param);
                throw new Error('Error: unknown parameter type');
        }
    }

    #getSchemaFromStatusCode(resStatusCode, operationRes) {
        let f = operationRes.filter(r => r.statusCode.toString() == resStatusCode.toString());
        if (f.length === 0)
            f = operationRes.filter(r => r.statusCode === 'default');
        if (f.length === 1)
            return f[0].schema;
        else
            return undefined;
    }

    #schemaValidator(schema, data, ajv) {
        if (!schema)
            return { valid: null, errors: ['No schema for this status code'] }; /// que hace aca?
        try {
            let d = JSON.parse(data);
            let validate = ajv.compile(schema);
            let valid = validate(d);
            return { valid: valid, errors: validate.errors };
        } catch (e) {
            return { valid: false, errors: [e.message] };
        }
    }

    #redisConnect() {
        if (!this.#redis) {
            this.#redis = redis.createClient({
                url: `redis://${process.env.REDIS_HOST}:${process.env.REDIS_PORT}`
            });
            this.#redis.on("error", (err) => console.error("Redis connect error: ", err));
            this.#redis.connect()
                .then(() => console.info(`Redis connected successfully!: PID`, process.pid))
                .catch(console.error);
        }
    }

    async publishEvent(channel, message) {

        if (!this.#redis) {
            console.error('[publishEvent] Redis no connected!');
            return;
        }

        try {
            message.data = btoa(JSON.stringify(message.data));
            await this.#redis.publish(channel, JSON.stringify(message));
            console.debug(`[publishEvent] Published event: ${channel}:`, message);
        } catch (error) {
            console.error('[publishEvent] Event exception:', error);
        }
    }


};

const jDozerFuzzerEngineProcessor = new JDozerFuzzerEngineProcessor();

module.exports = {

    async beforeScenario(context, event) {
        await jDozerFuzzerEngineProcessor.beforeScenario(context, event);
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