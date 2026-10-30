/**
 * Roadmap 13: which resolver a tunnel is given. Kept apart from users.ts,
 * which reaches the API server-side, so client components can import it.
 */
export type DnsProfile = "default" | "ads" | "family";

export const DNS_PROFILE_LABEL: Record<DnsProfile, string> = {
  default: "Default (this server's resolver)",
  ads: "Block ads and trackers",
  family: "Family (ads and adult sites blocked)",
};
