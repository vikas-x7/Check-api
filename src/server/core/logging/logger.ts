export type LogMeta = Record<string, unknown>;

export enum LogLevel {
    DEBUG = "DEBUG",
    INFO = "INFO",
    WARN = "WARN",
    ERROR = "ERROR",
}

export class Logger {
    constructor(private readonly component = "app") {}

    private format(level: LogLevel, message: string, meta?: LogMeta): string {
        const timestamp = new Date().toISOString();
        const payload: Record<string, unknown> = {
            timestamp,
            level,
            component: this.component,
            message,
            ...((meta && Object.keys(meta).length > 0) ? { meta } : {}),
        };
        return JSON.stringify(payload);
    }

    debug(message: string, meta?: LogMeta): void {
        if (process.env.NODE_ENV !== "production") {
            console.debug(this.format(LogLevel.DEBUG, message, meta));
        }
    }

    info(message: string, meta?: LogMeta): void {
        console.info(this.format(LogLevel.INFO, message, meta));
    }

    warn(message: string, meta?: LogMeta): void {
        console.warn(this.format(LogLevel.WARN, message, meta));
    }

    error(message: string, meta?: LogMeta): void {
        console.error(this.format(LogLevel.ERROR, message, meta));
    }

    child(component: string): Logger {
        return new Logger(`${this.component}:${component}`);
    }
}

export const logger = new Logger("server");
