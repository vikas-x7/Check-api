import { Suspense } from "react";
import Sidebar from "@/client/dashboard/components/Sidebar";
import ScanForm from "@/client/scanner/components/ScanForm";

export default function NewScanPage() {
    return (
        <div className="flex min-h-screen bg-[#0F0F0F]">
            <Sidebar />
            <main className="flex-1 h-screen overflow-y-auto">
                {/* Fixed Top Bar */}
                <div className="sticky top-0 bg-[#0F0F0F]/90 backdrop-blur-md border-b border-[#2D2D2D] px-5 py-4 z-20">
                    <h1 className="text-[24px] font-serif -tracking-[1px] text-[#E7E7E7]">
                        New Scan
                    </h1>
                    <p className="text-sm text-[#797979] mt-1">
                        Configure and launch a new security scan
                    </p>
                </div>

                {/* Scrollable Content */}
                <div className="flex-1 overflow-y-auto px-4 pb-10 pt-6">
                    <Suspense fallback={
                        <div className="flex items-center justify-center min-h-[400px]">
                            <div className="animate-pulse px-8 py-4 rounded-[4px] bg-[#1A1A1A] text-[#797979]">
                                Loading scan form...
                            </div>
                        </div>
                    }>
                        <ScanForm />
                    </Suspense>
                </div>
            </main>
        </div>
    );
}
