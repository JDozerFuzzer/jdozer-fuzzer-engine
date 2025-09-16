/**
    # JDozerFuzzer - Microservicio de Discovery
    # Copyright (C) 2024 Cristián Saéz V.
    # Licencia: GNU AGPLv3 (ver LICENSE)
 */
import { Logger } from "@nestjs/common";
import { randomUUID, UUID } from "crypto";


export class KeyManager {

    private readonly log = new Logger(KeyManager.name);

    private readonly JDF: string = 'JDF';

    public forFuzz(id: UUID): string {
        return this.JDF.concat(':').concat(id.toString());
    }

    public forOperation(operationName: string, fuzzerId: UUID): string {
        return this.forFuzz(fuzzerId).concat(':OP:', operationName);
    }

    public forFake(operation: string, context: string, fuzzerId: UUID): string {
        return this.forFuzz(fuzzerId).concat(':DMM:', operation, ':', context, ':', randomUUID().toString());
    }

    public forEngine(fuzzerId: UUID): string {
        return this.forFuzz(fuzzerId).concat(':ENG');
    }

    public forApi(fuzzerId: UUID): string {
        return this.forFuzz(fuzzerId).concat(':API');
    }

    public getUUIDForFuzz(fuzz: string): UUID {
        return fuzz.split(':')[1] as UUID;
    }

    public getUUIDForOperation(operation: string): UUID {
        return operation.split(':')[3] as UUID;
    }

    public getDMMAllKeys(fuzzerId: UUID): string {
        return this.forFuzz(fuzzerId).concat(':DMM:*');
    }

}