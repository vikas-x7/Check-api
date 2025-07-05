"use client";

import { motion } from "framer-motion";
import Link from "next/link";
import Navbar from "@/client/home/components/Navbar";
import { knowledgeItems, knowledgeCategoriesList } from "./data";
import { FiShield, FiCode, FiGlobe, FiLock, FiDatabase } from "react-icons/fi";

const categoryIcons: Record<string, React.ReactNode> = {
  owasp: <FiShield className="w-6 h-6" />,
  vulnerabilities: <FiCode className="w-6 h-6" />,
  "best-practices": <FiGlobe className="w-6 h-6" />,
  authentication: <FiLock className="w-6 h-6" />,
  "data-protection": <FiDatabase className="w-6 h-6" />,
};

const categoryColors: Record<string, string> = {
  owasp: "from-indigo-500 to-purple-500",
  vulnerabilities: "from-red-500 to-orange-500",
  "best-practices": "from-green-500 to-emerald-500",
  authentication: "from-blue-500 to-cyan-500",
  "data-protection": "from-amber-500 to-yellow-500",
};

export default function KnowledgeBaseHub() {
  const groupedItems = knowledgeCategoriesList.map((cat) => ({
    ...cat,
    items: knowledgeItems.filter((item) => item.category === cat.id),
  }));

  return (
    <div className="min-h-screen bg-slate-950 text-slate-200 selection:bg-indigo-500/30">
      <Navbar />

      <div className="max-w-7xl mx-auto px-6 py-16">
        <motion.div
          initial={{ opacity: 0, y: -20 }}
          animate={{ opacity: 1, y: 0 }}
          className="text-center mb-16"
        >
          <div className="inline-flex items-center gap-2 px-4 py-2 rounded-full bg-indigo-500/10 border border-indigo-500/20 text-indigo-400 text-sm font-bold uppercase tracking-wider mb-6">
            Security Knowledge Hub
          </div>
          <h1 className="text-4xl md:text-6xl font-black bg-gradient-to-r from-indigo-400 via-purple-400 to-pink-400 bg-clip-text text-transparent mb-6">
            Learn API Security
          </h1>
          <p className="text-lg md:text-xl text-slate-400 max-w-3xl mx-auto">
            Explore comprehensive guides on OWASP vulnerabilities, common
            attacks, and best practices to secure your APIs.
          </p>
        </motion.div>

        {groupedItems.map((category, catIndex) => (
          <motion.div
            key={category.id}
            initial={{ opacity: 0, y: 20 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ delay: catIndex * 0.1 }}
            className="mb-16"
          >
            <div className="flex items-center gap-3 mb-6">
              <div
                className={`w-12 h-12 rounded-xl flex items-center justify-center bg-gradient-to-br ${categoryColors[category.id]} shadow-lg`}
              >
                {categoryIcons[category.id]}
              </div>
              <div>
                <h2 className="text-2xl font-black text-white">
                  {category.name}
                </h2>
                <p className="text-sm text-slate-400">
                  hello{category.description}
                </p>
              </div>
            </div>

            <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
              {category.items.map((item, i) => (
                <Link
                  key={item.id}
                  href={`/knowledge/${item.id}`}
                  className="block focus:outline-none focus:ring-2 focus:ring-indigo-500/50 rounded-3xl"
                >
                  <motion.div
                    initial={{ opacity: 0, scale: 0.95, y: 20 }}
                    animate={{ opacity: 1, scale: 1, y: 0 }}
                    transition={{
                      delay: catIndex * 0.1 + i * 0.05,
                      duration: 0.4,
                    }}
                    className="h-full p-6 rounded-3xl border border-slate-800 bg-slate-900/50 hover:bg-slate-800/80 hover:border-slate-700 transition-all duration-300 group hover:-translate-y-2 hover:shadow-[0_10px_40px_-10px_rgba(99,102,241,0.2)] relative overflow-hidden flex flex-col"
                  >
                    <div
                      className={`absolute top-0 inset-x-0 h-1 bg-gradient-to-r ${item.color} opacity-50 group-hover:opacity-100 transition-opacity`}
                    />

                    <div className="flex items-center justify-between mb-6">
                      {item.severity && (
                        <span
                          className={`px-2.5 py-1 rounded-md text-[11px] font-bold uppercase tracking-wider border ${
                            item.severity === "Critical"
                              ? "bg-red-500/10 text-red-500 border-red-500/20"
                              : item.severity === "High"
                                ? "bg-orange-500/10 text-orange-400 border-orange-500/20"
                                : item.severity === "Medium"
                                  ? "bg-yellow-500/10 text-yellow-400 border-yellow-500/20"
                                  : "bg-blue-500/10 text-blue-400 border-blue-500/20"
                          }`}
                        >
                          {item.severity}
                        </span>
                      )}
                    </div>
                    <div className="flex items-center gap-4 mb-4">
                      <div
                        className={`w-14 h-14 rounded-2xl flex items-center justify-center text-2xl bg-gradient-to-br ${item.color} shadow-lg shrink-0 group-hover:scale-110 group-hover:rotate-3 transition-transform duration-300 relative`}
                      >
                        <div className="absolute inset-0 bg-white/20 rounded-2xl mix-blend-overlay opacity-0 group-hover:opacity-100 transition-opacity" />
                      </div>
                      <h3 className="text-xl font-bold text-slate-100 leading-tight group-hover:text-transparent group-hover:bg-clip-text group-hover:bg-gradient-to-r group-hover:from-white group-hover:to-slate-400 transition-all">
                        {item.title}
                      </h3>
                    </div>
                    <p className="text-sm text-slate-400 leading-relaxed flex-1 mt-2">
                      {item.shortDescription}
                    </p>
                    <div className="mt-6 flex items-center text-sm font-bold text-indigo-400 group-hover:text-indigo-300 transition-colors">
                      Study Detail{" "}
                      <span className="ml-2 group-hover:translate-x-1 transition-transform">
                        →
                      </span>
                    </div>
                  </motion.div>
                </Link>
              ))}
            </div>
          </motion.div>
        ))}
      </div>
    </div>
  );
}
