import { Injectable, Logger } from "@nestjs/common";
import { EngineConfigException } from "./EngineConfigException";


@Injectable()
export class EnginePhases {

    private readonly log: Logger = new Logger(EnginePhases.name);

    constructor() {
        this.log.verbose('[EnginePhases] Initializing Engine Phases...');
    }

    public build(scenarios: any[], totalCases: number, totalOps: number, length: number) {
        try {
            const phases = [];
            const seconds = length * 60;
            const securityFactor = 1.2;
            const arrivalRateBase = (totalCases / seconds) * securityFactor;

            const warmUp = {
                name: 'WarmUp',
                duration: Math.max(30, Math.round(length * 0.1 * 60)),
                arrivalRate: Math.round(arrivalRateBase * 0.3),
                maxVusers: Math.round(arrivalRateBase * 0.5)
            };

            const sustainedLoad = {
                name: 'SustainedLoad',
                duration: Math.round(length * 0.7 *60),
                arrivalRate: Math.round(arrivalRateBase),
                maxVusers: Math.round(arrivalRateBase * 1.5)
            };

            const rampDown = {
                name: "RampDown",
                duration: Math.round(length * 0.2 * 60),
                arrivalRate: Math.round(arrivalRateBase * 0.2),
                rampTo: 0
            };

            phases.push(warmUp, sustainedLoad, rampDown);
            this.log.verbose(`[build] Engine phases created: `, phases);
            return phases;
        } catch(e) {
            throw new EngineConfigException({ message: `Oops! Failed to build phases!`, details: e.message });
        }
    }

}