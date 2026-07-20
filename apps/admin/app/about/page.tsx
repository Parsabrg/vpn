import type { Metadata } from "next";

export const metadata: Metadata = {
  title: "About",
};

export default function AboutPage() {
  return (
    <section className="page-heading prose" aria-labelledby="about-title">
      <p className="eyebrow">About this build</p>
      <h1 id="about-title">Nebula Administration</h1>
      <p>
        This is the Phase 1.1 Next.js workspace for Nebula’s future
        administrator dashboard. Its current purpose is to prove the application
        shell, build, container, lint, type, and unit test paths.
      </p>
      <h2>Not available yet</h2>
      <ul>
        <li>Administrator authentication, MFA, sessions, and authorization</li>
        <li>Account request review or user management</li>
        <li>Control-plane, database, or VPN-agent connectivity</li>
        <li>WireGuard or Xray provisioning and runtime controls</li>
      </ul>
      <p className="notice">
        Do not treat this scaffold as an authenticated administration surface.
      </p>
    </section>
  );
}
