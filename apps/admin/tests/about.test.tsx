import { render, screen } from "@testing-library/react";

import AboutPage from "@/app/about/page";

describe("AboutPage", () => {
  it("documents the scaffold boundaries", () => {
    render(<AboutPage />);

    expect(
      screen.getByRole("heading", { level: 1, name: "Nebula Administration" }),
    ).toBeVisible();
    expect(
      screen.getByText(/do not treat this scaffold as an authenticated/i),
    ).toBeVisible();
    expect(screen.getByText(/WireGuard or Xray provisioning/i)).toBeVisible();
  });
});
