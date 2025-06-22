import { useMutation } from "@tanstack/react-query";
import { useRouter } from "next/navigation";
import { scannerService } from "../services/scanner.service";

export const useScanMutation = () => {
    const router = useRouter();

    return useMutation({
        mutationFn: scannerService.createScan,
        onSuccess: (data) => {
            router.push(`/dashboard/scans/${data.id}`);
        },
    });
};
