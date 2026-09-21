---
title: Home | bt_api_monitor
---

# bt_api_monitor Documentation

Performance monitoring system for the bt_api ecosystem. Provides real-time metrics collection, exchange health monitoring, and integrations with Prometheus, Grafana, and ELK stack.

## Overview

`bt_api_monitor` provides a comprehensive monitoring solution with:

- **Metrics** — Counter, Gauge, Histogram, Timer with Prometheus naming conventions
- **Decorators** — `@monitor_performance`, `@monitor_async_performance` for automatic profiling
- **Exchange Health** — ExchangeHealthMonitor for connection health checks
- **Observability** — Prometheus exporter, Grafana dashboard builder, ELK stack integration
- **System Metrics** — CPU, memory, disk, network usage tracking

## Key Benefits

- Zero-config global collector for quick adoption
- Async-aware monitoring decorators
- Standardized Prometheus-compatible metric format
- Grafana dashboard JSON generation out of the box
- Exchange-agnostic health check framework

## Quick Start

```python
from bt_api_monitor import MetricsCollector, counter, gauge, histogram

# Create and use metrics
counter("requests_total", tags={"endpoint": "/api/v1/ticker"}).inc()
gauge("active_connections", tags={"exchange": "binance"}).set(42)
histogram("request_latency_seconds", tags={"method": "GET"}).observe(0.123)
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
```

## Installation

```bash
pip install bt_api_monitor
```

## Rename notice

Use `bt_api_monitor` for new installations and imports.  The former
`bt_api_monitoring` import is temporarily supported with a deprecation warning
so existing callers can migrate deliberately.

## Dependencies

- psutil >= 5.9.0
- aiohttp >= 3.9.0
- pydantic >= 2.0.0

## API Reference

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

## Documentation

Full documentation available at [bt_api_py documentation](https://cloudquant.github.io/bt_api_py/).
