import { z } from "zod";

const envSchema = z.object({
    DATABASE_URL: z.string().min(1),
    NEXTAUTH_SECRET: z.string().min(1),
    NEXTAUTH_URL: z.string().url().optional(),
    VULNERABLE_API_URL: z.string().url().default("http://localhost:4000"),
});

export type Env = z.infer<typeof envSchema>;

export function getEnv(): Env {
    const parsed = envSchema.safeParse(process.env);
    if (!parsed.success) {
        console.error(" Invalid environment variables:", parsed.error.flatten().fieldErrors);
        throw new Error("Invalid environment variables");
    }
    return parsed.data;
}
