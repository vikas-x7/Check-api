"use client";

import { useState } from "react";
import Link from "next/link";
import { useAuth } from "../hooks/useAuth";
import { GiRoundShield } from "react-icons/gi";

export default function RegisterForm() {
  const { register, loading, error } = useAuth();
  const [name, setName] = useState("");
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    await register(name, email, password);
  };

  return (
    <div className="w-full text-white ">
      <div className="mb-8">
        <h1 className="text-2xl sm:text-2xl tracking-tight mb-2 text-white flex items-center gap-2">
          <GiRoundShield size={35} />
          Create account
        </h1>

        <p className="text-[11px] text-white/40 mb-7 max-w-xs leading-relaxed">
          Start organizing your documents, projects, and structured learning
          paths
        </p>
      </div>

      <form onSubmit={handleSubmit} className="space-y-4">
        <div className="flex flex-col gap-1.5">
          <label className="text-sm font-medium text-white/70">Full name</label>
          <input
            type="text"
            placeholder="John Doe"
            value={name}
            onChange={(e) => setName(e.target.value)}
            required
            minLength={2}
            className="w-full border border-white/10 bg-white/5 rounded-sm px-4 py-2 text-sm text-white placeholder-white/20 outline-none focus:border-white/30 transition-all"
          />
        </div>

        <div className="flex flex-col gap-1.5">
          <label className="text-sm font-medium text-white/70">
            Your email
          </label>
          <input
            type="email"
            placeholder="natalia.brak@knmstudio.com"
            value={email}
            onChange={(e) => setEmail(e.target.value)}
            required
            className="w-full border border-white/10 bg-white/5 rounded-sm px-4 py-2 text-sm text-white placeholder-white/20 outline-none focus:border-white/30 transition-all"
          />
        </div>

        <div className="flex flex-col gap-1.5">
          <label className="text-sm font-medium text-white/70">Password</label>
          <input
            type="password"
            placeholder="••••••••••••••••"
            value={password}
            onChange={(e) => setPassword(e.target.value)}
            required
            minLength={6}
            className="w-full border border-white/10 bg-white/5 rounded-sm px-4 py-2 text-sm text-white placeholder-white/20 outline-none focus:border-white/30 transition-all"
          />
        </div>

        {error && <p className="text-xs text-red-400">{error}</p>}

        <button
          type="submit"
          disabled={loading}
          className="w-full bg-[#F0EDE7] text-black/80 hover:bg-[#F0EDE7]/90 rounded-sm py-2 text-sm font-semibold tracking-wide disabled:opacity-50 disabled:cursor-not-allowed transition-all mt-1"
        >
          {loading ? "Creating account..." : "Create account"}
        </button>
      </form>

      <p className="text-center text-sm text-white/30 mt-6">
        Already have an account?{" "}
        <Link
          href="/login"
          className="text-white/90 font-medium hover:underline transition-colors"
        >
          Sign in
        </Link>
      </p>
    </div>
  );
}
