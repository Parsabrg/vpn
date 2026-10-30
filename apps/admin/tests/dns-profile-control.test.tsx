import { render, screen } from "@testing-library/react";
import { describe, expect, it, vi } from "vitest";
import { DnsProfileControl } from "@/components/dns-profile-control";

vi.mock("@/lib/users-actions", () => ({
  setDnsProfile: vi.fn(),
  setDeviceDnsProfile: vi.fn(),
}));

describe("DnsProfileControl", () => {
  it("names the account's profile", () => {
    render(<DnsProfileControl userId="u" initialProfile="family" />);
    // Once as the current value, once as the dialog's option.
    expect(
      screen.getAllByText(/Family \(ads and adult sites blocked\)/).length,
    ).toBeGreaterThan(0);
  });

  it("says a device without its own profile follows the account", () => {
    render(<DnsProfileControl userId="u" deviceId="d" initialProfile={null} />);
    expect(screen.getAllByText(/Follows the account/).length).toBeGreaterThan(
      0,
    );
  });
});
