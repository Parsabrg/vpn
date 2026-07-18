import { render, screen } from "@testing-library/react";

import HealthPage from "@/app/health/page";
import { GET } from "@/app/api/health/route";

describe("HealthPage", () => {
  it("does not imply that disconnected services are healthy", () => {
    render(<HealthPage />);

    expect(
      screen.getByRole("heading", { level: 1, name: "Scaffold health" }),
    ).toBeVisible();
    expect(
      screen.getByText(/not a control-plane or VPN health check/i),
    ).toBeVisible();
    expect(screen.getAllByText("Not connected")).toHaveLength(2);
  });
});

describe("GET /api/health", () => {
  it("reports liveness without claiming runtime capabilities", async () => {
    const response = GET();

    expect(response.status).toBe(200);
    await expect(response.json()).resolves.toMatchObject({
      service: "nebula-admin",
      status: "ok",
      capabilities: {
        authentication: false,
        controlPlane: false,
        vpnManagement: false,
      },
    });
  });
});
