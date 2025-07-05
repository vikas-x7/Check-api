const owaspItems = [
  "Broken Object Level Authorization",
  "Broken Authentication",
  "Broken Object Property Level Authorization",
  "Unrestricted Resource Consumption",
  "Broken Function Level Authorization",
  "Unrestricted Access to Sensitive Business Flows",
  "Server Side Request Forgery",
  "Security Misconfiguration",
  "Improper Inventory Management",
  "Unsafe Consumption of APIs",
];

export default function OwaspCoverage() {
  return (
    <section className="py-16 px-6 max-w-[900px] mx-auto">
      <div className="text-center mb-8">
        <h2 className="text-3xl font-extrabold mb-3">
          OWASP API Security{" "}
          <span className="bg-linear-to-br from-[--color-accent] to-[--color-cyan] text-transparent bg-clip-text">
            Top 10
          </span>{" "}
          Mapping
        </h2>
      </div>

      <div className="bg-[--color-bg-card] border border-[--color-border] rounded-xl p-6 transition-all duration-300">
        {owaspItems.map((item, index) => (
          <div
            key={item}
            className={`flex items-center gap-4 py-3 ${
              index < owaspItems.length - 1
                ? "border-b border-[--color-border]"
                : ""
            }`}
          >
            <div className="w-7 h-7 rounded-md bg-linear-to-br from-[--color-accent] to-[--color-cyan] flex items-center justify-center text-xs font-bold shrink-0">
              {index + 1}
            </div>
            <span className="text-sm">
              API{index + 1}:2023 — {item}
            </span>
          </div>
        ))}
      </div>
    </section>
  );
}
