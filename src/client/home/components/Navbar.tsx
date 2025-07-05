"use client";

import Link from "next/link";
import { useState } from "react";
import { GiRoundShield } from "react-icons/gi";

export default function Navbar() {
  const [menuOpen, setMenuOpen] = useState(false);

  const navItems = ["Home", "Features", "Reports", "Coverage"];

  return (
    <nav className="relative z-50 flex items-center justify-between px-4 sm:px-6 md:px-10 py-4 w-full max-w-7xl mx-auto border-x border-[#38352e] bg-[#0F0F0F]">
      <div className="flex w-full items-center justify-between  ">
        <Link href="/" className="flex items-center text-[#E6ECEC] gap-2 ">
          <GiRoundShield size={25} className="text-[#0F0F0F] bg-[#E6ECEC] rounded-[3px]" />
          <span className="text-[18px] font-bold -tracking-[1px]">
            Securiscane
          </span>
        </Link>

        <div className="hidden md:flex items-center gap-8">
          {navItems.map((item) => (
            <a
              key={item}
              href="#"
              className="text-sm text-[#E6ECEC] hover:text-[#E6ECEC]/60 transition-colors tracking-wide"
            >
              {item}
            </a>
          ))}
        </div>
        <div className="hidden md:flex items-center gap-4">
          <Link
            href="/login"
            className="px-5 py-1 bg-[#F0EDE7] text-black text-sm font-medium rounded-sm hover:bg-stone-700 hover:text-white transition-colors  tracking-wide"
          >
            Login
          </Link>
        </div>
        <button
          className="md:hidden p-2 flex flex-col justify-center items-center gap-1"
          onClick={() => setMenuOpen(!menuOpen)}
          aria-label="Toggle menu"
          aria-expanded={menuOpen}
        >
          <span
            className={`block w-5 h-0.5 bg-[#E6ECEC] transition-all duration-300 ${
              menuOpen ? "rotate-45 translate-y-1.5" : ""
            }`}
          />
          <span
            className={`block w-5 h-0.5 bg-[#E6ECEC] transition-all duration-300 ${
              menuOpen ? "opacity-0" : ""
            }`}
          />
          <span
            className={`block w-5 h-0.5 bg-[#E6ECEC] transition-all duration-300 ${
              menuOpen ? "-rotate-45 -translate-y-1.5" : ""
            }`}
          />
        </button>
      </div>

      {menuOpen && (
        <div className="absolute top-full left-0 right-0 bg-[#1B1913] border-b border-[#38352e] px-6 py-5 flex flex-col gap-4 md:hidden z-50">
          {navItems.map((item) => (
            <a
              key={item}
              href="#"
              className="text-sm  text-[#E6ECEC]/70 hover:text-[#E6ECEC] transition-colors"
              onClick={() => setMenuOpen(false)}
            >
              {item}
            </a>
          ))}
          <hr className="border-[#38352e]" />
          <Link
            href="/login"
            className="text-sm  text-[#E6ECEC]/70 hover:text-[#E6ECEC] transition-colors"
            onClick={() => setMenuOpen(false)}
          >
            Login
          </Link>
          <Link
            href="/register"
            className="px-5 py-2 bg-[#F0EDE7] text-black text-sm text-center rounded-sm hover:bg-stone-300 transition-colors"
            onClick={() => setMenuOpen(false)}
          >
            Start Scan
          </Link>
        </div>
      )}
    </nav>
  );
}
