import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { beforeEach, describe, expect, it, vi } from "vitest";
import { PermissionsPanel } from "@/components/permissions-panel";
import type { UserPermissionListItem } from "@/lib/access";
import type { ProtocolProfileListItem } from "@/lib/topology";

const grantPermissions = vi.hoisted(() => vi.fn());

vi.mock("@/lib/access-actions", () => ({
  grantPermission: vi.fn(),
  grantPermissions,
  revokePermission: vi.fn(),
}));

function profile(id: string, displayName: string): ProtocolProfileListItem {
  return {
    id,
    protocolId: "p",
    code: id,
    version: 1,
    displayName,
    state: "active",
    transport: null,
    transportSecurity: null,
    requiresUdp: false,
    isFullTunnel: true,
  };
}

function granted(p: ProtocolProfileListItem): UserPermissionListItem {
  return {
    id: `perm-${p.id}`,
    protocolProfileId: p.id,
    profileCode: p.code,
    profileDisplayName: p.displayName,
    state: "enabled",
    grantedByAdminId: null,
    grantedAt: "2026-09-22T12:00:00Z",
    expiresAt: null,
    revokedAt: null,
  };
}

const reality = profile("a", "Reality");
const hysteria = profile("b", "Hysteria2");
const wireguard = profile("c", "WireGuard");
const profiles = [reality, hysteria, wireguard];

describe("grant all", () => {
  beforeEach(() => {
    grantPermissions.mockReset();
  });

  it("grants every profile the user lacks, in one request", async () => {
    // One request is one change against the admin limit, which twelve
    // separate grants per user exhausted (2026-10-29).
    grantPermissions.mockResolvedValue({
      ok: true,
      data: [granted(hysteria), granted(wireguard)],
    });
    const user = userEvent.setup();
    render(
      <PermissionsPanel
        userId="u1"
        initialPermissions={[granted(reality)]}
        profiles={profiles}
      />,
    );

    await user.click(screen.getByRole("button", { name: "Grant all (2)" }));
    await user.click(screen.getByRole("button", { name: "Grant all" }));

    expect(grantPermissions.mock.calls).toEqual([["u1", ["b", "c"]]]);
    expect(screen.getByText("Hysteria2")).toBeInTheDocument();
    expect(screen.getByText("WireGuard")).toBeInTheDocument();
  });

  it("says when the admin limit refused it, and grants nothing", async () => {
    grantPermissions.mockResolvedValue({
      ok: false,
      code: "rate_limited",
      message:
        "Too many changes in a short time. Wait a few minutes, then try again.",
    });
    const user = userEvent.setup();
    render(
      <PermissionsPanel
        userId="u1"
        initialPermissions={[granted(reality)]}
        profiles={profiles}
      />,
    );

    await user.click(screen.getByRole("button", { name: "Grant all (2)" }));
    await user.click(screen.getByRole("button", { name: "Grant all" }));

    expect(screen.getByText(/Too many changes/)).toBeInTheDocument();
    expect(
      screen.getByRole("table", { name: "Permissions" }),
    ).not.toHaveTextContent("Hysteria2");
  });
});
