/**
    # JDozerFuzzer - Microservicio de Discovery
    # Copyright (C) 2024 Cristián Saéz V.
    # Licencia: GNU AGPLv3 (ver LICENSE)
 */
import { Logger } from "@nestjs/common";

export class EngineException extends Error {

    private readonly log = new Logger(EngineException.name);

    constructor(error: { message: string, details?: string }) {
        super(error.message);
        this.name = 'EngineException';
        this.log.error(`${error.toString()} - ${error.details}`);
    }

}