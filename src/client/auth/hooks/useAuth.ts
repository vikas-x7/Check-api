import { useState } from "react";
import { signIn } from "next-auth/react";
import { useRouter } from "next/navigation";
import { authService } from "../services/auth.service";

export const useAuth = () => {
    const router = useRouter();
    const [loading, setLoading] = useState(false);
    const [error, setError] = useState("");

    const login = async (email: string, password: string) => {
        setLoading(true);
        setError("");

        const result = await signIn("credentials", {
            email,
            password,
            redirect: false,
        });

        if (result?.error) {
            setError("Invalid email or password");
            setLoading(false);
        } else {
            router.push("/dashboard");
        }
    };

    const register = async (name: string, email: string, password: string) => {
        setLoading(true);
        setError("");

        try {
            await authService.register(name, email, password);
            router.push("/login?registered=true");
        } catch (err: unknown) {
            const axiosErr = err as { response?: { data?: { error?: string } } };
            setError(axiosErr.response?.data?.error || "Registration failed");
            setLoading(false);
        }
    };

    return { login, register, loading, error };
};
