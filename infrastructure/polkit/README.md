# polkit rules

`49-nebula-xray-agent.rules` grants the `nebula-agent` system user permission
to manage exactly the `nebula-xray.service` unit (start/stop/restart/reload),
nothing else. Systemd unit control is polkit-gated, not capability-gated, so
this is the correct minimal-privilege mechanism -- not sudo, not root.

Install on the host:

```bash
cp infrastructure/polkit/49-nebula-xray-agent.rules /etc/polkit-1/rules.d/
chown root:root /etc/polkit-1/rules.d/49-nebula-xray-agent.rules
chmod 0644 /etc/polkit-1/rules.d/49-nebula-xray-agent.rules
```

polkit watches `rules.d/` and picks up new files automatically. If a change
doesn't seem to take effect, `systemctl restart polkit` forces a reload.

Without this rule, every call the agent's `NativeXrayDriver` makes to
`systemctl reload-or-restart nebula-xray` fails with "Interactive
authentication required" -- discovered live against the real VPS deployment,
where it surfaced as an unhandled 500 (both the initial apply and its
rollback retry hit the same denial, propagating
`drivers/errors.py::RollbackFailedError` uncaught).
