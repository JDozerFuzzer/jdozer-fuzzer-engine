import { UUID } from "crypto";
import { RedisEventsGateway } from "./RedisEventGateway";


export class CasesCount {

    private redisEventsGateway: RedisEventsGateway;

    constructor(redisEventsGateway: RedisEventsGateway) {
        this.redisEventsGateway = redisEventsGateway;
    }

    public async send(fuzzerId: UUID, casesKeys: string[]) {
        const operations = this.count(casesKeys);
        const payload = {
            fuzzerId,
            cases: {
                total: casesKeys.length,
                operations: operations
            }
        }
        await this.redisEventsGateway.publish(fuzzerId, 'total-cases', payload);
    }

    private count(casesKeys: string[]) {
        // JDF:139eb537-88ac-4334-ba8e-857241495201:DMM:addPet:payload:0081a30b-ea17-4195-ae73-89539ced841d
        let operations: {} = {};
        casesKeys.forEach(k => {
            let s = k.split(':');
            if (operations[`${s[3]}`]) {
                if (operations[`${s[3]}`][`${s[4]}`]) {
                    operations[`${s[3]}`][`${s[4]}`]++;
                } else {
                    operations[`${s[3]}`][`${s[4]}`] = 1;
                }
            } else {
                operations[`${s[3]}`] = {};
                operations[`${s[3]}`][`${s[4]}`] = 1;
            }
        });
        return operations;
    }

}