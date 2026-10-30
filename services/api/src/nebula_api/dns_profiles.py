"""DNS profiles (roadmap 13; 108 D27-D29): the resolver a tunnel is given.

An account has one; a device may override it. Handed to Xray clients as
`client_dns`, which the app puts in the tunnel's DNS settings. An ad-blocking
protocol profile still uses its own filtering resolver -- the app decides
that -- so "ads" here is for the plain profiles.
"""

from typing import Literal

DnsProfile = Literal["default", "ads", "family"]
DNS_PROFILES: tuple[DnsProfile, ...] = ("default", "ads", "family")

# AdGuard DNS: its filtering resolver blocks ads and trackers; its family one
# also blocks adult sites and enforces safe search. Reached through the
# tunnel, from the server, like any other address.
_PUBLIC: dict[str, list[str]] = {
    "ads": ["94.140.14.14", "94.140.15.15"],
    "family": ["94.140.14.15", "94.140.15.16"],
}


def resolvers_for(profile: str, deployment_dns: str) -> list[str]:
    """The `client_dns` list: the deployment's own resolver for "default"
    (empty when it runs none, so the app keeps its own), a public filtering
    one otherwise."""

    if profile in _PUBLIC:
        return list(_PUBLIC[profile])
    return [deployment_dns] if deployment_dns else []


def effective_profile(user_profile: str, device_profile: str | None) -> str:
    return device_profile or user_profile
