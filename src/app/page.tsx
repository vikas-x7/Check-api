import Navbar from "@/client/home/components/Navbar";

import FAQ from "@/client/home/components/FAQ";
import { Hero } from "@/client/home/components/HeroSection";

export default function LandingPage() {
  return (
    <div className="min-h-screen bg-[#0F0F0F]">
      {/* Fixed Navbar */}
      <div className="fixed top-0 left-0 right-0 z-50 border-b border-dashed border-[#52514e] ">
        <div className="w-7xl mx-auto border-x border-dashed border-[#52514e]">
          <Navbar />
        </div>
      </div>

      {/* Main Content */}
      <div className="flex flex-col items-center justify-center min-h-screen  ">
        <div className="w-full max-w-7xl border-x border-dashed border-[#52514e] px-2 sm:px-4">
          <div className="flex items-center justify-center min-h-[calc(100vh-200px)]">
            <Hero />
          </div>
        </div>
      </div>

      {/* Footer */}
      <footer className="border-t border-[#38352e] py-8 px-6 text-center text-[#E6ECEC]/60 text-[13px] font-mono">
        <p>
          SecuriScan — API Security Analyzer & Penetration Test Report Generator
        </p>
        <p className="mt-2 text-xs">
          For authorized security testing only. Built with ❤️ for the
          cybersecurity community.
        </p>
      </footer>
    </div>
  );
}
