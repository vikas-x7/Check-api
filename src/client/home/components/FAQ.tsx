"use client";

import Image from "next/image";
import { useState } from "react";

const faqs = [
  {
    question: "What is SecuriScan?",
    answer:
      "SecuriScan is an API security analyzer that tests endpoint URLs and optional OpenAPI or Swagger specs, then generates structured penetration test reports.",
  },
  {
    question: "What does it test for?",
    answer:
      "It checks for missing authentication, excessive data exposure, missing rate limiting, HTTP method fuzzing issues, CORS misconfiguration, IDOR, and verbose error messages.",
  },
  {
    question: "Do I need an OpenAPI file?",
    answer:
      "No. You can scan a live API endpoint by itself, or upload an OpenAPI or Swagger file to improve coverage and compare the documented surface with the real one.",
  },
  {
    question: "What is included in the report?",
    answer:
      "Each report includes OWASP API Security Top 10 mapping, evidence for findings, risk details, and remediation code or guidance for fixing the issues.",
  },
  {
    question: "Is this safe to use?",
    answer:
      "Yes, as long as you only test systems you are authorized to assess. SecuriScan is built for responsible security testing and validation.",
  },
];

export default function FAQ() {
  const [activeIndex, setActiveIndex] = useState<number | null>(null);

  return (
    <section className="w-full py-16 px-4 font-gothic mt-30">
      <div className="max-w-6xl mx-auto grid grid-cols-1 lg:grid-cols-2 gap-20 items-start">
        <h2 className="text-4xl sm:text-5xl lg:text-[40px] -tracking-[1px] text-[#EDECEC] font-instrument mb-10">
          Frequently Asked <br /> Questions
        </h2>
        <div className="flex flex-col gap-1">
          <div className="border-t border-white/20 mt-2">
            {faqs.map((f, i) => (
              <div
                key={i}
                className="border-b border-white/20  cursor-pointer"
                onClick={() => setActiveIndex(activeIndex === i ? null : i)}
              >
                <div className="flex items-center justify-between py-4">
                  <span
                    className={`font-medium text-[18px] transition-colors duration-200 ${
                      activeIndex === i ? "text-white" : "text-white"
                    }`}
                  >
                    {f.question}
                  </span>
                  <span
                    className={`text-white/90 text-lg transition-transform duration-300 ${
                      activeIndex === i ? "rotate-45" : "rotate-0"
                    }`}
                  >
                    +
                  </span>
                </div>

                <div
                  className={`overflow-hidden transition-all duration-300 ease-in-out ${
                    activeIndex === i ? "max-h-40 pb-4" : "max-h-0"
                  }`}
                >
                  <p className="text-gray-500 text-sm leading-relaxed">
                    {f.answer}
                  </p>
                </div>
              </div>
            ))}
          </div>
        </div>
      </div>
    </section>
  );
}
