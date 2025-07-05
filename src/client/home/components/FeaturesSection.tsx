import {
  FiUnlock,
  FiPackage,
  FiZap,
  FiShuffle,
  FiGlobe,
  FiKey,
  FiAlertTriangle,
} from "react-icons/fi";

export default function FeaturesSection() {
  const features = [
    {
      icon: <FiUnlock className="w-6 h-6 text-indigo-400" />,
      title: "Authentication Testing",
      description:
        "Detect missing or broken authentication mechanisms across all API endpoints.",
      owasp: "API2:2023",
    },
    {
      icon: <FiPackage className="w-6 h-6 text-indigo-400" />,
      title: "Data Exposure Analysis",
      description:
        "Identify sensitive data leakage in API responses — emails, passwords, tokens.",
      owasp: "API3:2023",
    },
    {
      icon: <FiZap className="w-6 h-6 text-indigo-400" />,
      title: "Rate Limit Detection",
      description:
        "Burst-test endpoints to verify rate limiting and throttling controls.",
      owasp: "API4:2023",
    },
    {
      icon: <FiShuffle className="w-6 h-6 text-indigo-400" />,
      title: "HTTP Method Fuzzing",
      description:
        "Test all HTTP methods to find unintended allowed operations.",
      owasp: "API5:2023",
    },
    {
      icon: <FiGlobe className="w-6 h-6 text-indigo-400" />,
      title: "CORS Misconfiguration",
      description:
        "Detect wildcard origins, credential headers, and reflection-based flaws.",
      owasp: "API8:2023",
    },
    {
      icon: <FiKey className="w-6 h-6 text-indigo-400" />,
      title: "IDOR Detection",
      description:
        "Insecure Direct Object Reference checks via ID manipulation.",
      owasp: "API1:2023",
    },
    {
      icon: <FiAlertTriangle className="w-6 h-6 text-indigo-400" />,
      title: "Error Leakage",
      description:
        "Find stack traces, file paths, and debug info in error responses.",
      owasp: "API8:2023",
    },
  ];

  return (
    <section id="features" className="py-16 px-6 max-w-[1200px] mx-auto">
      <div className="text-center mb-12">
        <h2 className="text-3xl font-extrabold mb-3">
          Automated API Security{" "}
          <span className="bg-linear-to-br from-[--color-accent] to-[--color-cyan] text-transparent bg-clip-text">
            Checks
          </span>
        </h2>
        <p className="text-[--color-text-secondary] max-w-[500px] mx-auto">
          Seven focused tests covering the most critical API security risks and
          reporting outputs.
        </p>
      </div>

      <div className="grid grid-cols-[repeat(auto-fill,minmax(320px,1fr))] gap-5">
        {features.map((feature) => (
          <div
            key={feature.title}
            className="flex flex-col gap-3 bg-[--color-bg-card] border border-[--color-border] rounded-xl p-6 transition-all duration-300 hover:border-[--color-accent] hover:shadow-[0_0_20px_var(--color-accent-glow)] group"
          >
            <div className="flex items-center gap-3">
              <div className="shrink-0">{feature.icon}</div>
              <div>
                <h3 className="text-base font-semibold">{feature.title}</h3>
                <span className="inline-flex items-center px-2.5 py-0.5 mt-1 rounded-full text-[11px] font-semibold uppercase tracking-wider bg-[#6366f1]/10 text-[--color-accent] border border-[#6366f1]/30">
                  {feature.owasp}
                </span>
              </div>
            </div>
            <p className="text-sm text-[--color-text-secondary] leading-relaxed">
              {feature.description}
            </p>
          </div>
        ))}
      </div>
    </section>
  );
}
