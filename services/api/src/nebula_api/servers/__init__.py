"""Read-only, user-scoped listing of the VPN servers and protocol profiles a
caller is actually permitted to use.

Exists specifically so a client has a real way to learn a valid
`server_code` before calling `POST /v1/devices/{device_id}/wireguard-peer` --
previously only `topology_admin`'s admin-session-gated listing existed, and
Phase 1.7a's Flutter client shipped its devices/connect screens as an honest
empty state rather than guess at or hardcode one.
"""
