import { render, screen } from "@testing-library/react";

import OverviewPage from "@/app/page";

describe("OverviewPage", () => {
  it("states that runtime security and VPN capabilities are absent", () => {
    render(<OverviewPage />);

    expect(
      screen.getByRole("heading", {
        level: 1,
        name: "Administration scaffold",
      }),
    ).toBeVisible();
    expect(
      screen.getByText(
        /no runtime authentication or VPN functionality is implemented/i,
      ),
    ).toBeVisible();
    expect(screen.getByRole("link", { name: "View health" })).toHaveAttribute(
      "href",
      "/health",
    );
  });

  it("labels every current implementation state", () => {
    render(<OverviewPage />);

    expect(screen.getByText("Scaffolded")).toBeVisible();
    expect(screen.getByText("Not implemented")).toBeVisible();
    expect(screen.getByText("Not connected")).toBeVisible();
  });
});
