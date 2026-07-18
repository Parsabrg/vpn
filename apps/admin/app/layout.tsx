import type { Metadata } from "next";

import { SiteHeader } from "@/components/site-header";

import "./globals.css";

export const metadata: Metadata = {
  title: {
    default: "Nebula Administration",
    template: "%s | Nebula Administration",
  },
  description: "Nebula VPN administration scaffold",
};

export default function RootLayout({
  children,
}: Readonly<{ children: React.ReactNode }>) {
  return (
    <html lang="en">
      <body>
        <a className="skip-link" href="#main-content">
          Skip to main content
        </a>
        <SiteHeader />
        <main id="main-content" className="page-shell" tabIndex={-1}>
          {children}
        </main>
        <footer className="site-footer">
          <p>Nebula Phase 1.1 scaffold — no production controls are active.</p>
        </footer>
      </body>
    </html>
  );
}
