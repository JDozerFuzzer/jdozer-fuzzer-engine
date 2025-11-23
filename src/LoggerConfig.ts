import { ConsoleLogger, LogLevel } from "@nestjs/common";

export class LoggerConfig {

    public static logLevels(appName: string): ConsoleLogger {
        const logger = new ConsoleLogger(appName);
        const logLevel: LogLevel[] = [];
        this.loggerMapper().forEach(level => {
            logLevel.push(level as LogLevel);
        });
        logger.setLogLevels(logLevel);
        return logger;
    }

    private static loggerMapper(): string[] {
        const level: string = process.env.FUZZER_LOG_LEVEL;
        if (level === 'INFO')
            return ['error', 'warn', 'log'];
        if (level === 'DEBUG')
            return ['error', 'warn', 'log', 'debug'];
        if (level === 'TRACE')
            return ['error', 'warn', 'log', 'debug', 'verbose', 'fatal'];
        if (level === 'WARN')
            return ['error', 'warn'];
        if (level === 'ERROR')
            return ['error'];
        return ['error', 'warn', 'log'];
    }

}