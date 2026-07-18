import type { Metadata } from "next";

import { StatusCard } from "@/components/status-card";

export const metadata: Metadata = {
  title: "Health",
};

export default function HealthPage() {
  return (
    <>
      <section className="page-heading" aria-labelledby="health-title">
        <p className="eyebrow">Deployment visibility</p>
        <h1 id="health-title">Scaffold health</h1>
        <p>
          This page confirms that the admin web process can render. It is not a
          control-plane or VPN health check.
        </p>
      </section>
      <section className="status-grid" aria-label="Service health">
        <StatusCard title="Admin web process" status="scaffolded">
          <p>
            The Next.js application is available and serving this static
            placeholder.
          </p>
        </StatusCard>
        <StatusCard title="Control plane API" status="not-connected">
          <p>
            No API client or authenticated server-side facade has been
            implemented.
          </p>
        </StatusCard>
        <StatusCard title="VPN runtime" status="not-connected">
          <p>
            No VPN agent, WireGuard, or Xray health information is queried by
            this application.
          </p>
        </StatusCard>
      </section>
    </>
  );
}
