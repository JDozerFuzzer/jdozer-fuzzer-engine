import { Injectable, Logger } from "@nestjs/common";
import { RedisService } from "../persistence/RedisService";
import { KeyManager } from "../persistence/KeyManager";
import { EngineConfigException } from "./EngineConfigException";


@Injectable()
export class EngineScenarios {

    private readonly log: Logger = new Logger(EngineScenarios.name);

    constructor() {
        this.log.verbose('[EngineScenarios] Initializing Engine Scenarios...');
    }

    public async build(operations: any[], cases: string[]) {
        try {
            const operationWeight = await this.operationWeight(operations, cases);
            const scenarios = [];
            for (const op of operations) {
                scenarios.push({
                    name: `${op.name}`,
                    beforeScenario: 'beforeScenario',
                    weight: operationWeight[op.name].weight,
                    flow: [
                        {
                            [op.method]: {
                                url: op.path,
                                beforeRequest: 'beforeRequest',
                                afterResponse: 'afterResponse'
                            }
                        }
                    ]
                });
            }
            return scenarios;
        } catch (e) {
            throw new EngineConfigException({ message: `Oops! Failed to build scenarios!`, details: e.message });
        }
    }

    private async operationWeight(operations: any[], cases: string[]): Promise<any> {
        try {
            let opWeight = {};
            this.log.verbose(opWeight);
            for (const op of operations) {
                opWeight[`${op.name}`] = {};
                opWeight[`${op.name}`].cant = cases.filter(c => c.includes(op.name)).length;
                opWeight[`${op.name}`].weight = (opWeight[op.name].cant * 100) / cases.length;
            }
            opWeight = this.shorted(opWeight);
            opWeight = this.optimize(opWeight);
            this.log.verbose(`[operationWeight] Operation weights calculated: `, opWeight);
            return opWeight;
        } catch (e) {
            throw new EngineConfigException({ message: `Oops! Failed to calculate scenarios!`, details: e.message });
        }
    }

    private shorted(operationWeight: any): any {
        return Object.fromEntries(
            Object.entries(operationWeight).sort(([, a], [, b]) => (b as any).weight - (a as any).weight)
        );
    }

    private optimize(operationWeight: any): any {

        const entries = Object.entries(operationWeight);
        const activeOps = entries.filter(([, op]) => (op as any).weight > 0);
        const lowWeightOps = activeOps.filter(([, op]) => (op as any).weight < 1);
        const highWeightOps = activeOps.filter(([, op]) => (op as any).weight >= 1);

        const weightToAdd = lowWeightOps.length;
        const totalHighWeight = highWeightOps.reduce((sum, [, op]) => sum + (op as any).weight, 0);

        const reductionFactor = (totalHighWeight - weightToAdd) / totalHighWeight;

        const result = {};
        entries.forEach(([key, op]) => {
            const prop = (op as any);
            if (prop.weight === 0) {
                result[key] = prop;
            } else if (prop.weight < 1) {
                result[key] = { ...prop, weight: 1 };
            } else {
                result[key] = { ...prop, weight: Math.max(1, prop.weight * reductionFactor) };
            }
        });
        return result;
    }

}