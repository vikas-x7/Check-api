export interface ApiErrorOptions {
    code?: string;
    statusCode?: number;
    details?: Record<string, unknown>;
}

export class ApiError extends Error {
    public readonly statusCode: number;
    public readonly code: string;
    public readonly details: Record<string, unknown> | undefined;

    constructor(message: string, { code = "E_INTERNAL", statusCode = 500, details }: ApiErrorOptions = {}) {
        super(message);
        this.name = "ApiError";
        this.statusCode = statusCode;
        this.code = code;
        this.details = details;
    }

    static badRequest(message = "Bad Request", details?: ApiErrorOptions["details"]) {
        return new ApiError(message, { statusCode: 400, code: "E_BAD_REQUEST", details });
    }

    static unauthorized(message = "Unauthorized", details?: ApiErrorOptions["details"]) {
        return new ApiError(message, { statusCode: 401, code: "E_UNAUTHORIZED", details });
    }

    static notFound(message = "Resource not found", details?: ApiErrorOptions["details"]) {
        return new ApiError(message, { statusCode: 404, code: "E_NOT_FOUND", details });
    }

    static conflict(message = "Conflict", details?: ApiErrorOptions["details"]) {
        return new ApiError(message, { statusCode: 409, code: "E_CONFLICT", details });
    }

    static internal(message = "Internal Server Error", details?: ApiErrorOptions["details"]) {
        return new ApiError(message, { statusCode: 500, code: "E_INTERNAL", details });
    }
}
