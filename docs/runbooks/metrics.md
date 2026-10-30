# Metrics

The API and the VPN agent publish Prometheus metrics on the server's loopback
only:

| Service | Address | Main series |
| --- | --- | --- |
| API | `http://127.0.0.1:8000/metrics` | `nebula_api_requests_total{method,route,status}`, `nebula_api_request_seconds` |
| Agent | `http://127.0.0.1:9464/metrics` | `nebula_agent_requests_total{method,route,status}`, `nebula_agent_request_seconds` |

Both add the usual `process_*` series (memory, CPU, open files). Routes are
templates (`/v1/admin/users/{user_id}`), never raw paths. From outside, nginx
answers `/metrics` with 404, and the agent's metrics port is not opened in the
firewall. The agent's port is `NEBULA_AGENT_METRICS_PORT` in `agent.env`
(default 9464; 0 turns it off).

## Reading them

Prometheus on the same server:

```yaml
scrape_configs:
  - job_name: nebula-api
    static_configs: [{ targets: ["127.0.0.1:8000"] }]
  - job_name: nebula-agent
    static_configs: [{ targets: ["127.0.0.1:9464"] }]
```

From elsewhere, over SSH rather than by opening a port:
`ssh -L 9090:127.0.0.1:9090 <server>` to a Prometheus there, or
`ssh -L 8000:127.0.0.1:8000 <server>` for a quick look.

`infrastructure/grafana/nebula.json` is a Grafana dashboard for these jobs
(Dashboards → Import): requests by status, the 95th-percentile time to answer,
5xx by route, agent operations, memory and CPU.
