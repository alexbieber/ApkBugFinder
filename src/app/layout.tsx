import type { Metadata } from "next";
import { Inter, JetBrains_Mono } from "next/font/google";
import { Header } from "@/components/header";
import "./globals.css";

const inter = Inter({
  subsets: ["latin"],
  variable: "--font-inter",
});

const jetbrainsMono = JetBrains_Mono({
  subsets: ["latin"],
  variable: "--font-jetbrains",
});

export const metadata: Metadata = {
  title: "Apkbugfinder — OWASP MASVS Android Security Scanner",
  description:
    "Advanced static security analysis for Android APK files. Scan for vulnerabilities based on OWASP MASVS — entirely in your browser.",
  keywords: ["APK", "Android", "security", "MASVS", "SAST", "OWASP"],
  icons: { icon: "/favicon.svg" },
};

export default function RootLayout({
  children,
}: Readonly<{
  children: React.ReactNode;
}>) {
  return (
    <html lang="en" className={`${inter.variable} ${jetbrainsMono.variable}`}>
      <body className="font-sans">
        <Header />
        <main>{children}</main>
      </body>
    </html>
  );
}
