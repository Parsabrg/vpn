import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { describe, expect, it, vi } from "vitest";

import OverviewLoading from "@/app/(protected)/loading";
import OverviewError from "@/app/(protected)/error";
import RequestsLoading from "@/app/(protected)/requests/loading";
import RequestsError from "@/app/(protected)/requests/error";
import AuditLogLoading from "@/app/(protected)/audit-log/loading";
import AuditLogError from "@/app/(protected)/audit-log/error";
import EmailDeliveriesLoading from "@/app/(protected)/email-deliveries/loading";
import EmailDeliveriesError from "@/app/(protected)/email-deliveries/error";
import UsersLoading from "@/app/(protected)/users/loading";
import UsersError from "@/app/(protected)/users/error";
import UserDetailLoading from "@/app/(protected)/users/[userId]/loading";
import UserDetailError from "@/app/(protected)/users/[userId]/error";
import ServerHealthLoading from "@/app/(protected)/server-health/loading";
import ServerHealthError from "@/app/(protected)/server-health/error";
import PermissionsLoading from "@/app/(protected)/permissions/loading";
import PermissionsError from "@/app/(protected)/permissions/error";
import AssignmentsLoading from "@/app/(protected)/assignments/loading";
import AssignmentsError from "@/app/(protected)/assignments/error";

const segments = [
  { name: "overview", Loading: OverviewLoading, Error: OverviewError },
  { name: "requests", Loading: RequestsLoading, Error: RequestsError },
  { name: "audit log", Loading: AuditLogLoading, Error: AuditLogError },
  {
    name: "email deliveries",
    Loading: EmailDeliveriesLoading,
    Error: EmailDeliveriesError,
  },
  { name: "users", Loading: UsersLoading, Error: UsersError },
  { name: "user detail", Loading: UserDetailLoading, Error: UserDetailError },
  {
    name: "server health",
    Loading: ServerHealthLoading,
    Error: ServerHealthError,
  },
  { name: "permissions", Loading: PermissionsLoading, Error: PermissionsError },
  { name: "assignments", Loading: AssignmentsLoading, Error: AssignmentsError },
];

describe.each(segments)("$name route segment", ({ Loading, Error }) => {
  it("renders a loading status", () => {
    render(<Loading />);
    expect(screen.getByRole("status")).toBeVisible();
  });

  it("renders a generic, non-leaking error message and retries via reset()", async () => {
    const user = userEvent.setup();
    const reset = vi.fn();
    render(<Error reset={reset} />);

    const alert = screen.getByRole("alert");
    expect(alert).toBeVisible();
    expect(alert.textContent).not.toMatch(/error:|stack|undefined|null/i);

    await user.click(screen.getByRole("button", { name: "Try again" }));
    expect(reset).toHaveBeenCalledTimes(1);
  });
});
