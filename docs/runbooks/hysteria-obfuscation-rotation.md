# Rotating the Hysteria2 obfuscation password

The Salamander obfuscation password is **one secret shared by every client**.
This is correct use of the protocol, and it is worth writing down precisely
because it looks like a credential and is not one.

## What it is, and what it is not

It is censorship resistance. It makes the UDP port look like nothing in
particular to anything scanning or classifying traffic, and it is applied
before authentication, so a probe without it gets no response at all.

It is **not access control.** Per-device authentication is separate, is real,
and is the thing that decides who may use the tunnel: the server renders one
`userpass` entry per provisioned device, so revoking a device removes its
entry and its access. Someone holding only the obfuscation password can reach
the port and gets rejected.

Two consequences follow from it being shared, and both are permanent
properties of the protocol rather than defects to be fixed:

- Any single compromised device discloses the value that makes the port
  reachable. Not the tunnel -- the port.
- Rotation is all-or-nothing. Every client carries the same value, so changing
  it on the server cuts off every client that has not already received the new
  one.

Xray-core cannot serve this at all: it accepts a Salamander configuration and
silently discards it, so a client offering a deliberately wrong password
authenticates successfully. That is why Hysteria2 runs on the reference
implementation here. See `docs/adr/0004`.

## When to rotate

- A device is lost or seized, or a config is shared outside its intended user.
- The port starts being blocked in a way that suggests the obfuscation is
  known rather than the protocol being fingerprinted.
- On no schedule otherwise. Rotation costs every user a reconnect, and doing
  it routinely trains people to expect breakage, which is worse than the risk
  it addresses.

## Rotating

There is no staged rollout available: the server accepts exactly one value.
Plan for every client to be disconnected until it re-provisions.

1. Pick a new value. Any high-entropy string; it is never typed by a user.

   ```shell
   openssl rand -base64 24
   ```

2. Set `NEBULA_XRAY_HYSTERIA_OBFS_PASSWORD` in `/etc/nebula/agent.env` on the
   VPN server.

3. Restart the agent so it reads the new value:

   ```shell
   systemctl restart nebula-vpn-agent
   ```

   This does **not** yet change anything a client sees. The agent renders the
   Hysteria2 config only inside an apply, and an apply happens on a provision
   or a revoke -- not on a restart, and not on a reconciliation sweep that
   finds everything in sync. Until then `/etc/nebula/hysteria/config.yaml`
   still holds the old password and the running server still accepts it.

4. Trigger an apply. Connecting one device on the Hysteria2 profile is the
   simplest: that provision re-renders the config, notices it differs, writes
   it, and restarts the service.

   That first reconnect is also what cuts everyone else off, so it is the
   moment the rotation actually takes effect -- not step 2, and not step 3.
   Do it deliberately rather than letting it happen to whichever user
   reconnects first.

5. Confirm the file changed and the service came back:

   ```shell
   grep -A 2 "obfs:" /etc/nebula/hysteria/config.yaml
   systemctl is-active nebula-hysteria
   ```

6. Every remaining client re-provisions to receive the new value: disconnect,
   then connect again on the Hysteria2 profile. Provisioning returns the
   current obfuscation password with the response, so nothing is typed by
   hand.

## Verifying it is actually enforced

A wrong password must fail. This is worth checking after a rotation, because
the failure mode that shipped here once was obfuscation being configured and
silently ignored, which looks identical to obfuscation working:

```shell
/opt/nebula-vpn-agent/.venv/bin/nebula-agent-check
```

That reports the endpoint as `SKIP` -- Hysteria2 is QUIC over UDP and cannot
be checked by connecting. The real test is a client with a deliberately wrong
obfuscation password: it must fail to connect. If it succeeds, obfuscation is
not being applied, whatever the config says.
