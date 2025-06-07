import { ApiError } from "./api-error";
import { logger } from "@/server/core/logging/logger";

export function handleError(error: unknown) {
    if (error instanceof ApiError) {
        logger.warn("Handled ApiError", {
            code: error.code,
            status: error.statusCode,
            details: error.details,
            message: error.message,
        });

        return {
            status: error.statusCode,
            payload: {
                error: error.message,
                code: error.code,
                details: error.details,
            },
        };
    }

    if (error instanceof Error) {
        logger.error("Unhandled exception", {
            name: error.name,
            message: error.message,
            stack: error.stack,
        });

        return {
            status: 500,
            payload: {
                error: "Internal server error",
                code: "E_INTERNAL",
            },
        };
    }

    logger.error("Unknown error type thrown", { value: error });

    return {
        status: 500,
        payload: { error: "Internal server error", code: "E_INTERNAL" },
    };
}
