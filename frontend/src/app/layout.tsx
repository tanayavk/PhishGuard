import type { Metadata } from "next";
// @ts-ignore Next.js processes this global stylesheet import.
import "./globals.css";

export const metadata: Metadata = {
  title: "PhishGuard | Zero-Trust Email Security",
  description:
    "Agentic AI-Based Zero-Trust Email Security Gateway",
};

export default function RootLayout({
  children,
}: Readonly<{
  children: React.ReactNode;
}>) {
  return (
    <html lang="en">
      <body>{children}</body>
    </html>
  );
}