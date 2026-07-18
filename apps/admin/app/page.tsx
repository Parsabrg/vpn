import Link from "next/link";

import { StatusCard } from "@/components/status-card";

export default function OverviewPage() {
  return (
    <>
      <section className="hero" aria-labelledby="overview-title">
        <p className="eyebrow">Phase 1.1</p>
        <h1 id="overview-title">Administration scaffold</h1>
        <p className="hero__summary">
          This shell establishes the admin application workspace and its quality
          checks. It does not yet authenticate administrators, call the control
          plane, or manage VPN services.
        </p>
        <div className="notice" role="status">
          <strong>Safe placeholder:</strong> no runtime authentication or VPN
          functionality is implemented.
        </div>
      </section>

      <section className="status-grid" aria-label="Implementation status">
        <StatusCard title="Application shell" status="scaffolded">
          <p>
            Accessible navigation, responsive layout, TypeScript, linting, and
            tests are ready.
          </p>
        </StatusCard>
        <StatusCard title="Administrator access" status="not-implemented">
          <p>
            Sign-in, MFA, sessions, CSRF protection, and authorization arrive in
            Phase 1.3.
          </p>
        </StatusCard>
        <StatusCard title="Control plane and VPN" status="not-connected">
          <p>
            No database, VPN agent, WireGuard, or Xray operations are available
            from this UI.
          </p>
        </StatusCard>
      </section>

      <section className="next-step" aria-labelledby="next-step-title">
        <div>
          <p className="eyebrow">Current capability</p>
          <h2 id="next-step-title">Inspect scaffold health</h2>
          <p>
            Review build identity and the intentionally disconnected service
            states.
          </p>
        </div>
        <Link className="button-link" href="/health">
          View health
        </Link>
      </section>
    </>
  );
}
