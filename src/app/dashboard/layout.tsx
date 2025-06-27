import Sidebar from "@/client/dashboard/components/Sidebar";

export default function DashboardLayout({ children }: { children: React.ReactNode }) {
    return (
        <div className="flex min-h-screen bg-black">
            <Sidebar />
            <main className="flex-1 p-0 bg-[#0F0F0F] overflow-y-auto text-white">
                {children}
            </main>
        </div>
    );
}