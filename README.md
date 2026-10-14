# bt_api_monitor

[![Python 3.9-3.14](https://img.shields.io/badge/python-3.9--3.14-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](https://opensource.org/licenses/MIT)

Performance monitoring system for the bt_api ecosystem. Provides real-time metrics collection, exchange health monitoring, and integrations with Prometheus, Grafana, and ELK stack.

## Features

### Core Monitoring
- **MetricsCollector** — Centralized metrics collection with global collector support
- **Counter / Gauge / Histogram** — Standard metric types with Prometheus naming conventions
- **PerformanceTimer** — High-precision timing utilities for performance profiling

### Decorators
- `@monitor_performance` — Decorator for automatic performance monitoring
- `@monitor_async_performance` — Async-aware performance monitoring decorator
- `@monitor_calls` — Call count and frequency monitoring

### Exchange Health
- **ExchangeHealthMonitor** — Health check framework for exchange connections
- **HealthCheck / HealthCheckResult** — Standardized health check types
- **HealthStatus** — Enum for UP / DOWN / DEGRADED states

### Observability Integrations
- **PrometheusExporter** — Push metrics to Prometheus Pushgateway
- **GrafanaDashboardBuilder** — Generate Grafana dashboard JSON configs
- **ELKIntegration** — Elasticsearch / Logstash / Kibana integration via `ElasticsearchClient` and `LogstashHandler`

### System Metrics
- **SystemMetricsCollector** — CPU, memory, disk, network usage tracking
- **BusinessMetricsCollector** — Custom business-level metric collection

## Installation

```bash
pip install bt_api_monitor
```

### Rename notice

The canonical distribution and import are now `bt_api_monitor`.  The former
`bt_api_monitoring` import remains as a deprecated compatibility shim for one
migration window; update imports before the next breaking release.

## Requirements

- Python >= 3.9
- psutil >= 5.9.0
- aiohttp >= 3.9.0
- pydantic >= 2.0.0

## Quick Start

```python
from bt_api_monitor import MetricsCollector, counter, gauge, histogram

# Use the global collector
collector = MetricsCollector()

# Increment a counter
counter("requests_total", tags={"endpoint": "/api/v1/ticker"}).inc()

# Set a gauge
gauge("active_connections", tags={"exchange": "binance"}).set(42)

# Record a histogram
histogram("request_latency_seconds", tags={"method": "GET"}).observe(0.123)

# Start global monitoring
from bt_api_monitor import start_global_monitoring, stop_global_monitoring

start_global_monitoring()
# ... your code ...
stop_global_monitoring()
```

### Exchange Health Check

```python
from bt_api_monitor import ExchangeHealthMonitor, HealthCheckFactory

monitor = ExchangeHealthMonitor()
check = HealthCheckFactory.create("binance_spot", timeout=5.0)
result = monitor.check_sync(check)
print(f"Status: {result.status}, latency: {result.latency_ms}ms")
```

### Prometheus Export

```python
from bt_api_monitor import start_prometheus_exporter, stop_prometheus_exporter

start_prometheus_exporter(port=9090)
# Metrics are now available at http://localhost:9090/metrics
```

## API Reference

### Durable event delivery and control ingress

`OutboxEvent` accepts redacted JSON facts. `DurableOutbox` stores them in SQLite
with event-ID deduplication and scoped checkpoints. `DurableOutboxConsumer`
calls an injected synchronous sink and advances the checkpoint only after the
sink returns. A sink can receive the same event again if it accepts an event
but the checkpoint write fails, so sinks should deduplicate by `event_id`.

### Optional remote durable event intake

The explicit `durable_ingress` service role exposes `events.append` on
`service.telemetry_ingress`. The default Monitor role remains read-only.
Durable event intake has its own operation grant; ordinary `telemetry.append`
does not authorize it. SDK clients must explicitly request `events.append`
on their `upstream.telemetry` binding. No optional service is enabled merely
by installing the package.

Service-manifest component fragment:

```yaml
components:
  monitor:
    config_schema_version: 2
    settings:
      instance_id: monitor-events
      bind_ports: [service.telemetry_ingress]
      options:
        role: durable_ingress
        max_events: 10000
        max_bytes: 67108864
        max_event_bytes: 65536
```

These limits are also the defaults when only the role is specified. The
trusted resource provider supplies a writable `DurableOutbox` and the
`WireScope -> MonitorIngressTarget` mapping; YAML cannot choose Python code.
The outbox closes its short-lived SQLite connections after each operation;
use `ComponentResources.borrowed` for this instance. The host owns its registry and
transport lifecycle. The default read role can run in a separate query host
over a read-only handle to the same database.

Only authenticated service identities can publish through this role. Trusted
server targets select the outbox scope and allowed event types. A request has
exactly `schema_version: 1`, `event_id`, `event_type`, `occurred_at`, and `data`;
it cannot select an account, principal, outbox scope, or producer identity.
The adapter stores trusted producer metadata separately from the supplied
payload and namespaces the event ID by producer and authorized scope.

An accepted reply reports the persisted sequence and server event ID. An
exact retry with the same source ID and content returns the original sequence,
including after restart; conflicting content is rejected. A timeout or lost
reply does not prove absence. The SDK does not automatically retry; a producer
must retain the original ID and content for an explicit replay after normal
runtime recovery. This intake does not itself create a producer-side outbox or
make order dispatch and monitor delivery one transaction.
Source event IDs must stay unique within the logical producer and authorized
scope across process runs. A new run ID does not turn a reused source event ID
into a new fact; identical content is still the same event.

`DurableOutbox.append_bounded` checks event-count and retained logical UTF-8
byte limits in the same SQLite write transaction as insertion. Capacity
exhaustion rejects a new event without deleting existing facts; exact
duplicates remain readable at capacity. These are retained event limits,
not a hard limit on SQLite pages, indexes, or WAL size. The legacy local
`append` API keeps its existing behavior; other trusted writers sharing the
database must follow their own retention policy.

Use a separate permanently read-only outbox handle with `MonitorReadService`
for queries. Publishing a generic event does not certify a complete economic
fact, strategy ownership, account freshness, or portfolio PnL. Those consumers
must validate their domain schemas and provenance. This role also does not
implement lossy strategy heartbeats/metrics, monitoring control, or provider
connections.

### Control command verification

`ControlIngress` accepts a `ControlCommandEnvelope` only after an injected
verifier validates it. `HmacControlCommandVerifier` supports canonical HMAC
envelopes and exact, time-bound key and scope grants through injected resolver
interfaces. The package does not include a key store, issuer-policy source,
provider client, or command executor. `DurableControlLedger` persists verified
commands and coordinates owner claims; the account owner must independently
guard each action and record its outcome.

| Class / Function | Description |
|-----------------|-------------|
| `MetricsCollector` | Centralized metrics collector |
| `Counter(name, tags)` | Increment-only metric |
| `Gauge(name, tags)` | Settable metric |
| `Histogram(name, tags)` | Distribution metric |
| `timer(name, tags)` | Context manager for timing |
| `ExchangeHealthMonitor` | Exchange health monitoring |
| `PrometheusExporter` | Prometheus push gateway exporter |
| `GrafanaDashboardBuilder` | Grafana dashboard JSON generator |
| `ELKIntegration` | Elasticsearch/Logstash integration |
| `SystemMetricsCollector` | System resource metrics |
| `DurableOutbox` / `DurableOutboxConsumer` | SQLite event outbox with at-least-once delivery |
| `ControlIngress` / `DurableControlLedger` | Verified control ingress and durable owner claims |
| `HmacControlCommandVerifier` | HMAC envelope and exact-grant verification |

## Documentation

Full documentation available at [bt_api_py documentation](https://cloudquant.github.io/bt_api_py/).

## License

MIT License
