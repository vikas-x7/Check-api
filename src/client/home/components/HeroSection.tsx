/* eslint-disable @next/next/no-img-element */
"use client";
import FAQ from "@/client/home/components/FAQ";
import MarqueeSection from "@/client/home/components/MarqueeSection";
import Link from "next/link";
import { CiGlobe } from "react-icons/ci";
import { IoIosArrowRoundForward, IoMdDocument } from "react-icons/io";
import { SiFuturelearn } from "react-icons/si";

export const Hero = () => (
  <section className="relative flex flex-col items-center justify-center text-left overflow-hidden mt-16 sm:mt-20 md:mt-10  ">
    <div className="relative z-10 flex flex-col items-start w-full max-w-7xl mx-auto text-left mt-20 px-2 sm:px-4">
      <h1 className="text-4xl sm:text-5xl md:text-[47px]  text-[#D6D5D4]   mb-5 mt-4 font-medium  font-serif text-start -tracking-[1px]">
        Security Analyzer for Api <br /> Pen Test Reports OWASP Coverage
      </h1>

      <p className="text-sm text-[#F5F5F5]/50 max-w-lg mx-0 text-start">
        Scan endpoints, uncover flaws, and generate structured reports all
        inside one focused platform built for API security teams.
      </p>
    </div>
    <MarqueeSection />

    <div className="relative w-full h-screen max-w-7xl mt-12 sm:mt-16 md:mt-20 px-0">
      <img
        className="w-full rounded-sm opacity-35"
        src="https://i.pinimg.com/1200x/e9/b7/f0/e9b7f04adebdb4c71e5595315e052df8.jpg"
        alt=""
      />
      <img
        className="absolute w-[calc(100%-4.5rem)] rounded-lg"
        style={{
          left: "2.25rem",
          right: "2.25rem",
          top: "6%",
          width: "calc(100% - 4.5rem)",
          borderRadius: "8px",
        }}
        src="https://res.cloudinary.com/dr4fknnmp/image/upload/v1775009333/SecuriScan_kpo4ln.jpg"
        alt=""
      />
    </div>

    {/* Section Heading */}
    <div className="w-full max-w-7xl text-start mt-32 sm:mt-40 md:mt-52 mb-6 px-2">
      <h1 className="text-lg sm:text-xl md:text-[23px] text-[#E6ECEC]/90 text-center">
        All the Essential Tools to Test APIs, Review Findings and Generate{" "}
        <br />
        Clear Security Reports and Remediation Guidance
      </h1>
    </div>

    <div className="flex flex-col sm:flex-row justify-center gap-1 mt-6 mb-24 w-full max-w-7xl">
      <div className="w-full sm:w-64 md:w-72 h-72 sm:h-80 rounded-sm overflow-hidden relative shrink-0">
        <img
          src="https://i.pinimg.com/736x/ca/eb/4d/caeb4de0657fb92409b28549d36cabdc.jpg"
          alt="visual"
          className="w-full h-full object-cover opacity-50"
        />
        <h1 className="absolute bottom-6 left-6 text-white text-[16px]">
          Security Features
        </h1>
      </div>

      <a
        href="#"
        className="w-full sm:w-64 md:w-72 bg-[#1A1A1A] text-[#EDECEC] text-sm text-start rounded-sm border border-[#393732]/20 p-6 flex flex-col justify-between transition-all"
      >
        <div className="flex items-start justify-between">
          <div className="w-8 h-8 rounded-sm flex items-center justify-center">
            <IoMdDocument size={34} />
          </div>
          <span className="text-xs text-[#E6ECEC]/30">/01</span>
        </div>
        <h3 className="mt-6 text-base text-[#E6ECEC]/90">Endpoint Testing</h3>
        <ul className="mt-6 space-y-2 text-xs text-[#E6ECEC]/30">
          <li>✓ Missing auth checks</li>
          <li>✓ Excessive data exposure</li>
          <li>✓ Verbose error review</li>
          <li>✓ CORS policy checks</li>
          <li>✓ IDOR probing</li>
        </ul>
        <div className="mt-6 text-xs flex items-center gap-1">
          Learn more <span>↗</span>
        </div>
      </a>

      {/* Card 2 */}
      <a
        href="#"
        className="w-full sm:w-64 md:w-72 bg-[#1A1A1A] text-[#EDECEC] text-sm text-start rounded-sm border border-[#393732]/20 p-6 flex flex-col justify-between transition-all"
      >
        <div className="flex items-start justify-between">
          <div className="w-8 h-8 rounded-sm flex items-center justify-center">
            <SiFuturelearn size={25} />
          </div>
          <span className="text-xs text-[#E6ECEC]/30">/02</span>
        </div>
        <h3 className="mt-6 text-base text-[#E6ECEC]/90">Security Reports</h3>
        <ul className="mt-6 space-y-2 text-xs text-[#E6ECEC]/30">
          <li>✓ OWASP API mapping</li>
          <li>✓ Evidence for each issue</li>
          <li>✓ Remediation code snippets</li>
          <li>✓ Structured findings list</li>
          <li>✓ Export-ready summaries</li>
        </ul>
        <div className="mt-6 text-xs flex items-center gap-1">
          Learn more <span>↗</span>
        </div>
      </a>

      <a
        href="#"
        className="w-full sm:w-64 md:w-72 bg-[#1A1A1A] text-[#EDECEC] text-sm text-start rounded-sm border border-[#393732]/20 p-6 flex flex-col justify-between transition-all"
      >
        <div className="flex items-start justify-between">
          <div className="w-8 h-8 rounded-sm flex items-center justify-center">
            <CiGlobe size={25} />
          </div>
          <span className="text-xs text-[#E6ECEC]/30">/03</span>
        </div>
        <h3 className="mt-6 text-base text-[#E6ECEC]/90">OpenAPI Review</h3>
        <ul className="mt-6 space-y-2 text-xs text-[#E6ECEC]/30">
          <li>✓ Import Swagger or OpenAPI</li>
          <li>✓ Compare spec and live API</li>
          <li>✓ Detect hidden methods</li>
          <li>✓ Review auth coverage</li>
          <li>✓ Spot risky endpoints</li>
        </ul>
        <div className="mt-6 text-xs flex items-center gap-1">
          Learn more <span>↗</span>
        </div>
      </a>
    </div>

    <div className="w-full max-w-6xl mx-auto flex flex-col md:flex-row items-center justify-between gap-8 md:gap-12 mb-16 mt-16 px-2">
      <div className="flex-col text-start w-full md:max-w-xl">
        <h2 className="text-2xl sm:text-3xl text-[#EDECEC] mb-2">
          We bring everything you need to audit APIs into one place.
        </h2>
        <p className="mb-8 text-[#E6ECEC]/30 mt-3 text-sm sm:text-base">
          Enter an endpoint URL, attach an OpenAPI spec, and get findings with
          evidence, OWASP mapping, and clear remediation guidance.
        </p>
        <Link
          href="/login"
          className="px-5 py-1.5 bg-[#F0EDE7] text-black text-sm font-medium rounded-sm hover:bg-stone-700 transition-colors font-mono tracking-wide"
        >
          Start scanning
        </Link>
      </div>

      <div className="flex relative justify-center w-full md:w-auto">
        <img
          className="w-full max-w-xs sm:max-w-sm md:w-112.5 opacity-30
            mask-[radial-gradient(circle_at_center,black_5%,transparent_100%)]
            [-webkit-mask-image:radial-gradient(circle_at_center,black_5%,transparent_100%)]
            mask-no-repeat
            mask-size-[100%_100%]"
          src="https://cdn.prod.website-files.com/6812d02840d393aa2c663370/6847f9fe57cfb544f7d5818a_hero-home.svg"
          alt="Hero Background"
        />
      </div>
    </div>

    <FAQ />

    <div className="w-full max-w-6xl rounded-sm bg-[#1A1A1A] border border-[#393732]/20 mb-16 flex flex-col items-center justify-center py-16 px-6 mt-20 sm:mt-32 md:mt-40 text-center">
      <h1 className="text-[#E6ECEC]/80 mb-4 text-sm sm:text-base">
        Build Your Report, Document Your Findings, and Remediate With Direction
      </h1>
      <Link
        href="/login"
        className="px-5 py-1.5 bg-[#F0EDE7] text-black text-sm font-medium rounded-sm hover:bg-stone-700 transition-colors font-mono tracking-wide"
      >
        Try now
      </Link>
    </div>
  </section>
);
