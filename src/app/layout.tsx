import type { Metadata } from "next";
import { DM_Sans, PT_Serif } from "next/font/google";
import "./globals.css";
import { Providers } from "@/providers";

const dmSans = DM_Sans({
  subsets: ["latin"],
  display: "swap",
  variable: "--font-dm-sans",
});

const ptSerif = PT_Serif({
  subsets: ["latin"],
  weight: ["400", "700"],
  style: ["normal", "italic"],
  display: "swap",
  variable: "--font-pt-serif",
});

export const metadata: Metadata = {
  title: "SecuriScan ",
  description:
    "Automated API security analysis and penetration testing report generator. Test for OWASP API Security Top 10 vulnerabilities.",
  keywords: [
    "API security",
    "penetration testing",
    "OWASP",
    "vulnerability scanner",
  ],
};

export default function RootLayout({
  children,
}: {
  children: React.ReactNode;
}) {
  return (
    <html lang="en" className={`${dmSans.variable} ${ptSerif.variable}`} suppressHydrationWarning>
      <body className="font-sans">
        <Providers>{children}</Providers>
      </body>
    </html>
  );
}
