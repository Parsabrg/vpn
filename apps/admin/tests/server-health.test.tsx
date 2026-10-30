import { render, screen, within } from "@testing-library/react";
import { afterEach, expect, it, vi } from "vitest";
import ServerHealthPage from "@/app/(protected)/server-health/page";
import { apiFetch } from "@/lib/api/client";

vi.mock("@/lib/api/client", () => ({ apiFetch: vi.fn() }));

afterEach(() => vi.resetAllMocks());

const defaultProps = { searchParams: Promise.resolve({}) };
const emptyHistory = { items: [], total: 0, limit: 25, offset: 0 };

it("shows unsettled records even when the agent is unreachable", async () => {
  vi.mocked(apiFetch).mockImplementation(async (path) => {
    if (path === "/v1/admin/reconciliation-history") return emptyHistory;
    if (path === "/v1/admin/vpn-servers/xray-health") return { items: [] };
    if (path === "/v1/admin/traffic-summary") return { items: [] };
    if (path === "/v1/admin/vpn-servers") {
      return {
        items: [
          {
            id: "s1",
            code: "node-1",
            display_name: "Node 1",
            state: "maintenance",
            public_host: "vpn.example.test",
            maximum_devices: 100,
          },
        ],
      };
    }
    if (path === "/v1/admin/vpn-servers/health") {
      return {
        items: [
          {
            server_id: "s1",
            code: "node-1",
            state: "unreachable",
            observed_at: "2026-10-02T00:00:00Z",
            latency_ms: null,
            agent_version: null,
            interface_up: null,
            peer_count: null,
          },
        ],
      };
    }
    return {
      items: [
        {
          server_id: "s1",
          code: "node-1",
          pending_provisions: 2,
          pending_revocations: 3,
          failed_records: 1,
        },
      ],
    };
  });

  render(await ServerHealthPage(defaultProps));

  const table = screen.getByRole("table", { name: "Records not yet in sync" });
  expect(
    within(table)
      .getAllByRole("cell")
      .map((cell) => cell.textContent),
  ).toEqual(["node-1", "2", "3", "1"]);
  const card = screen.getByRole("article", { name: "Server Node 1" });
  expect(within(card).getByText("Agent unreachable")).toBeVisible();
  expect(
    screen.getByText("6 records are waiting or need review."),
  ).toBeVisible();
  expect(apiFetch).toHaveBeenCalledWith("/v1/admin/vpn-servers/reconciliation");
});

it.each([false, null])(
  "keeps Xray listener evidence independent of WireGuard health (%s)",
  async (listenerUp) => {
    vi.mocked(apiFetch).mockImplementation(async (path) => {
      if (path === "/v1/admin/reconciliation-history") return emptyHistory;
      if (path === "/v1/admin/vpn-servers")
        return {
          items: [
            {
              id: "s1",
              code: "node-1",
              display_name: "Node 1",
              state: "active",
              public_host: "vpn.example.test",
              maximum_devices: 100,
            },
          ],
        };
      if (path === "/v1/admin/vpn-servers/health")
        return {
          items: [
            {
              server_id: "s1",
              code: "node-1",
              state: "healthy",
              observed_at: "2026-10-02T00:00:00Z",
              latency_ms: 0,
              agent_version: "1.0.0",
              interface_up: true,
              peer_count: 0,
            },
          ],
        };
      if (path === "/v1/admin/vpn-servers/xray-health")
        return {
          items: [
            {
              server_id: "s1",
              code: "node-1",
              state: "unreachable",
              observed_at: "2026-10-02T00:00:01Z",
              latency_ms: listenerUp === null ? null : 0,
              agent_version: listenerUp === null ? null : "1.0.0",
              listener_up: listenerUp,
              error_code:
                listenerUp === null
                  ? "agent_unreachable"
                  : "listener_unreachable",
            },
          ],
        };
      return { items: [] };
    });
    render(await ServerHealthPage(defaultProps));
    const card = screen.getByRole("article", { name: "Server Node 1" });
    // WireGuard's own evidence stands, whatever Xray's probe said.
    expect(within(card).getByText("up · 0 peers")).toBeVisible();
    expect(within(card).getByTitle("2026-10-02T00:00:00.000Z")).toBeVisible();
    expect(
      within(card).getByText(
        listenerUp === null
          ? "Xray not checked · 0 ms"
          : "Xray listener down · 0 ms",
      ),
    ).toBeVisible();
    expect(
      within(card).getByText(
        listenerUp === null
          ? "unknown (agent_unreachable)"
          : "down (listener_unreachable)",
      ),
    ).toBeVisible();
    expect(apiFetch).toHaveBeenCalledWith("/v1/admin/vpn-servers/xray-health");
  },
);

it("propagates Xray inventory failure instead of inventing an empty probe set", async () => {
  vi.mocked(apiFetch).mockImplementation(async (path) => {
    if (path === "/v1/admin/vpn-servers/xray-health")
      throw new Error("health unavailable");
    return emptyHistory;
  });
  await expect(ServerHealthPage(defaultProps)).rejects.toThrow(
    "health unavailable",
  );
});

it("shows an empty inventory without claiming provisioning has not been implemented", async () => {
  vi.mocked(apiFetch).mockResolvedValue(emptyHistory);
  render(await ServerHealthPage(defaultProps));
  expect(screen.getByText("No servers yet")).toBeVisible();
  expect(screen.queryByText(/Phase 1.6/)).not.toBeInTheDocument();
  expect(screen.getByText("No traffic has been counted yet.")).toBeVisible();
});

it("shows global engine totals precisely and leaves missing samples unknown", async () => {
  vi.mocked(apiFetch).mockImplementation(async (path) => {
    if (path === "/v1/admin/traffic-summary")
      return {
        items: [
          {
            protocol: "wireguard",
            rx_bytes: "12",
            tx_bytes: "14",
            total_bytes: "26",
            newest_collected_at: "2026-10-02T00:00:00Z",
          },
          {
            protocol: "xray",
            rx_bytes: "9223372036854775809",
            tx_bytes: "9223372036854775811",
            total_bytes: "18446744073709551620",
            newest_collected_at: "2026-10-01T23:00:00Z",
          },
          {
            protocol: "hysteria2",
            rx_bytes: "0",
            tx_bytes: "0",
            total_bytes: "0",
            newest_collected_at: null,
          },
          {
            protocol: "constructor",
            rx_bytes: "1",
            tx_bytes: "2",
            total_bytes: "3",
            newest_collected_at: null,
          },
        ],
      };
    return emptyHistory;
  });
  render(await ServerHealthPage(defaultProps));
  const table = screen.getByRole("table", { name: "Traffic by engine" });
  expect(within(table).getByText("WireGuard")).toBeVisible();
  expect(within(table).getByText("Xray")).toBeVisible();
  expect(within(table).getByText("Hysteria2")).toBeVisible();
  expect(within(table).getByText("constructor")).toBeVisible();
  // Readable units, and the exact count, past a JS number's precision.
  expect(
    within(table).getByTitle("9,223,372,036,854,775,809 bytes"),
  ).toHaveTextContent("8.0 EB");
  expect(
    within(table).getByTitle("18,446,744,073,709,551,620 bytes"),
  ).toHaveTextContent("16.0 EB");
  expect(within(table).getByTitle("26 bytes")).toHaveTextContent("26 B");
  expect(within(table).getAllByText("0 B")).toHaveLength(3);
  expect(within(table).getAllByText("Unknown")).toHaveLength(2);
  expect(within(table).getByTitle("2026-10-02T00:00:00.000Z")).toBeVisible();
  expect(apiFetch).toHaveBeenCalledWith("/v1/admin/traffic-summary");
});

it("uses the error boundary when traffic totals are unavailable", async () => {
  vi.mocked(apiFetch).mockImplementation(async (path) => {
    if (path === "/v1/admin/traffic-summary")
      throw new Error("traffic unavailable");
    return emptyHistory;
  });
  await expect(ServerHealthPage(defaultProps)).rejects.toThrow(
    "traffic unavailable",
  );
});

it("propagates a failed summary request instead of showing zero pending removals", async () => {
  vi.mocked(apiFetch).mockImplementation(async (path) => {
    if (path === "/v1/admin/vpn-servers/reconciliation")
      throw new Error("API unavailable");
    return { items: [] };
  });
  await expect(ServerHealthPage(defaultProps)).rejects.toThrow(
    "API unavailable",
  );
});

it("shows historical evidence, keeps unknown generations distinct from zero and retains pagination filters", async () => {
  vi.mocked(apiFetch).mockImplementation(async (path) => {
    if (path !== "/v1/admin/reconciliation-history") return { items: [] };
    return {
      items: [
        {
          id: "r1",
          server_id: "s1",
          server_code: "node-1",
          target_kind: "wireguard_peer",
          target_id: "t1",
          desired_generation: 2,
          observed_generation: 0,
          outcome: "repair_failed",
          checked_at: "2026-10-02T00:00:00Z",
          error_code: "agent_unreachable",
        },
        {
          id: "r2",
          server_id: "s1",
          server_code: "node-1",
          target_kind: "xray_client",
          target_id: "t2",
          desired_generation: 1,
          observed_generation: null,
          outcome: "ambiguous",
          checked_at: "2026-10-01T23:59:00Z",
          error_code: null,
        },
      ],
      total: 52,
      limit: 25,
      offset: 25,
    };
  });
  render(
    await ServerHealthPage({
      searchParams: Promise.resolve({
        server_id: "s1",
        target_id: "t1",
        outcome: "repair_failed",
        offset: "25",
      }),
    }),
  );
  const table = screen.getByRole("table", { name: "Reconciliation checks" });
  expect(within(table).getByText("0")).toBeVisible();
  expect(within(table).getAllByText("Unknown")).toHaveLength(2);
  expect(within(table).getByText("Repair failed")).toBeVisible();
  expect(within(table).getByTitle("2026-10-02T00:00:00.000Z")).toBeVisible();
  expect(
    within(table).getByRole("link", { name: "wireguard_peer (t1)" }),
  ).toHaveAttribute("href", "/server-health?server_id=s1&target_id=t1");
  expect(screen.getByRole("link", { name: "Next" })).toHaveAttribute(
    "href",
    "/server-health?server_id=s1&target_id=t1&outcome=repair_failed&offset=50",
  );
  expect(apiFetch).toHaveBeenCalledWith("/v1/admin/reconciliation-history", {
    searchParams: {
      server_id: "s1",
      target_id: "t1",
      outcome: "repair_failed",
      limit: 25,
      offset: 25,
    },
  });
  // Folded away unless a filter is in use, as here.
  expect(screen.getByText("Reconciliation history (52)")).toBeVisible();
});

it("uses the existing error boundary when history cannot be retrieved", async () => {
  vi.mocked(apiFetch).mockImplementation(async (path) => {
    if (path === "/v1/admin/reconciliation-history")
      throw new Error("history unavailable");
    return { items: [] };
  });
  await expect(ServerHealthPage(defaultProps)).rejects.toThrow(
    "history unavailable",
  );
});
