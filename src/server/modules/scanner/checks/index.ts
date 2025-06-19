import { SecurityCheck } from "@/types";
import { AuthenticationCheck } from "./auth.check";
import { DataExposureCheck } from "./dataExposure.check";
import { RateLimitCheck } from "./rateLimit.check";
import { MethodFuzzCheck } from "./methodFuzz.check";
import { CorsCheck } from "./cors.check";
import { IdorCheck } from "./idor.check";
import { ErrorLeakCheck } from "./errorLeak.check";
import { JwtVulnerabilityCheck } from "./jwt.check";
import { SqlInjectionCheck } from "./sqli.check";
import { NoSqlInjectionCheck } from "./nosqli.check";
import { CommandInjectionCheck } from "./commandInjection.check";
import { FileUploadCheck } from "./fileUpload.check";
import { ApiVersioningCheck } from "./apiVersioning.check";
import { SsrfCheck } from "./ssrf.check";

export const ALL_CHECKS: SecurityCheck[] = [
    new AuthenticationCheck(),
    new DataExposureCheck(),
    new RateLimitCheck(),
    new MethodFuzzCheck(),
    new CorsCheck(),
    new IdorCheck(),
    new ErrorLeakCheck(),
    new JwtVulnerabilityCheck(),
    new SqlInjectionCheck(),
    new NoSqlInjectionCheck(),
    new CommandInjectionCheck(),
    new FileUploadCheck(),
    new ApiVersioningCheck(),
    new SsrfCheck(),
];

export {
    AuthenticationCheck,
    DataExposureCheck,
    RateLimitCheck,
    MethodFuzzCheck,
    CorsCheck,
    IdorCheck,
    ErrorLeakCheck,
    JwtVulnerabilityCheck,
    SqlInjectionCheck,
    NoSqlInjectionCheck,
    CommandInjectionCheck,
    FileUploadCheck,
    ApiVersioningCheck,
    SsrfCheck,
};
