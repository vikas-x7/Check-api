"use client";

const mindMapNodes = [
  { name: "Endpoint Scan" },
  { name: "Auth Checks" },
  { name: "Rate Limits" },
  { name: "Method Fuzzing" },
  { name: "CORS Review" },
  { name: "IDOR Testing" },
  { name: "Error Leakage" },
  { name: "OWASP Mapping" },
  { name: "Spec Diff" },
  { name: "Remediation" },
];

export default function MarqueeSection() {
  return (
    <section className="w-6xl overflow-hidden mt-13">
      <div className="relative flex border-y border-dashed border-black/10 py-3 sm:py-4 md:py-6">
        <div className="flex animate-marquee whitespace-nowrap">
          {[...mindMapNodes, ...mindMapNodes].map((node, i) => (
            <span
              key={i}
              className="text-[#b2b2b2] mx-5 sm:mx-8 md:mx-8 opacity-80 hover:opacity-100 transition-opacity duration-200 select-none text-[13px] sm:text-[15px] md:text-[17px]"
            >
              {node.name}
            </span>
          ))}
        </div>
      </div>
    </section>
  );
}
