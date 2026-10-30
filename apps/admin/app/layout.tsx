import type { Metadata } from "next";

import "./globals.css";

// Rendered per request, so Next can put proxy.ts's CSP nonce on its scripts:
// a page built ahead of time would carry none and be blocked.
export const dynamic = "force-dynamic";

export const metadata: Metadata = {
  title: {
    default: "Nebula Administration",
    template: "%s | Nebula Administration",
  },
  description: "Nebula VPN administration console",
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
        {children}
        <footer className="site-footer">
          <p>Nebula VPN administration.</p>
        </footer>
      </body>
    </html>
  );
}
