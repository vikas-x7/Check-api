"use client";

import Link from "next/link";
import { usePathname } from "next/navigation";
import { signOut, useSession } from "next-auth/react";
import {
  FiBarChart2,
  FiPlusSquare,
  FiShield,
  FiLogOut,
  FiList,
} from "react-icons/fi";
import { ImFire } from "react-icons/im";
import { GiDrippingTube, GiRoundShield } from "react-icons/gi";
import { HiUserGroup } from "react-icons/hi";
import { HiFolder } from "react-icons/hi";
import { HiBookOpen } from "react-icons/hi";

const navItems = [
  { href: "/dashboard", label: "Overview", icon: <FiBarChart2 /> },
  { href: "/scanner/new", label: "Testing", icon: <GiDrippingTube /> },
  { href: "/dashboard/result", label: "Results", icon: <FiList /> },
  { href: "/dashboard/projects", label: "Projects", icon: <HiFolder /> },
  { href: "/dashboard/teams", label: "Teams", icon: <HiUserGroup /> },
  { href: "/dashboard/knowledge", label: "Knowledge", icon: <HiBookOpen /> },
];

export default function Sidebar() {
  const pathname = usePathname();
  const { data: session } = useSession();

  return (
    <aside className="w-[220px] min-h-screen bg-[#0F0F0F] border-r border-[#2D2D2D] flex flex-col shrink-0 sticky top-0 h-screen">
      {/* Logo */}
      <div className="px-5 py-2 border-b border-[#2D2D2D]">
        <Link
          href="/dashboard"
          className="flex items-center gap-2.5 no-underline"
        >
          <div className="w-6 h-6 rounded-[2px]  bg-white text-black flex items-center justify-center ">
            <GiRoundShield size={25} />
          </div>
          <span className="font-serif -tracking-[1px] text-[19px] text-white ">
            SecuriScan
          </span>
        </Link>
      </div>

      <nav className="flex-1 px-3 py-4 flex flex-col  ">
        {navItems.map((item) => {
          const isActive =
            pathname === item.href ||
            (item.href !== "/dashboard" && pathname.startsWith(item.href));

          return (
            <Link
              key={item.href}
              href={item.href}
              className={`flex items-center gap-2 rounded-[4px] px-2 py-2 text-sm transition-all
                ${
                  isActive
                    ? "text-[#E7E7E7] bg-[#1A1A1A] font-semibold"
                    : "text-[#E7E7E7]/80 "
                }`}
            >
              <span>{item.icon}</span>
              {item.label}
            </Link>
          );
        })}
      </nav>

      {/* User section */}
      <div className="px-3 py-2 border-t border-[#2D2D2D] flex items-center gap-3">
        {session?.user && (
          <>
            <div className="w-7 h-7 rounded-[2px] bg-white text-black flex items-center justify-center font-bold text-xs shrink-0">
              {(session.user.name || session.user.email || "?")
                .charAt(0)
                .toUpperCase()}
            </div>
            <div className="min-w-0 flex-1 pr-1">
              <p className="text-white text-[12px] ">
                {session.user.name || "User"}
              </p>
              <p className="text-gray-500 text-[11px] truncate opacity-80">
                {session.user.email}
              </p>
            </div>
          </>
        )}

        <button
          onClick={() => signOut({ callbackUrl: "/" })}
          className="p-2 rounded-lg text-gray-400 transition-all hover:text-red-500 hover:bg-red-500/10 shrink-0"
          title="Sign Out"
        >
          <FiLogOut className="w-4.5 h-4.5" />
        </button>
      </div>
    </aside>
  );
}
