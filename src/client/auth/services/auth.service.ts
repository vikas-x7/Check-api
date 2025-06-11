import axios from "axios";

export const authService = {
    register: async (name: string, email: string, password: string) => {
        const response = await axios.post("/api/auth/register", { name, email, password });
        return response.data;
    }
};
