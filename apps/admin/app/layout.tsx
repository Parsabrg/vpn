import type { Metadata } from "next";

import "./globals.css";

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
