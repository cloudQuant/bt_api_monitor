"""
Performance monitoring system for bt_api_py.

This module provides comprehensive performance monitoring capabilities,
including real-time metrics collection, performance timing and profiling,
resource usage tracking, exchange health monitoring, alerts, and integrations
for Prometheus, Grafana, and ELK.

Public objects are loaded on first access so importing a narrow read-only
component does not initialize unrelated monitoring integrations.
"""

from __future__ import annotations

from importlib import import_module
from typing import Any

_EXPORT_MODULES = {
    **dict.fromkeys(
        (
            "MetricsCollector",
            "PerformanceMetrics",
            "get_global_collector",
            "start_global_monitoring",
            "stop_global_monitoring",
        ),
        ".collector",
    ),
    **dict.fromkeys(
        (
            "CheckpointError",
            "DurableOutbox",
            "DurableOutboxConsumer",
            "OutboxConflictError",
            "OutboxDeliveryCallable",
            "OutboxDeliveryError",
            "OutboxError",
            "OutboxEvent",
            "SequencedOutboxEvent",
        ),
        ".durable",
    ),
    **dict.fromkeys(
        (
            "ClaimedControlCommand",
            "ControlAction",
            "ControlAuthorizationError",
            "ControlCommandBinding",
            "ControlClaimError",
            "ControlCommand",
            "ControlCommandEnvelope",
            "ControlCommandVerifier",
            "ControlConflictError",
            "ControlIngress",
            "ControlLedgerError",
            "ControlOwnerOutcome",
            "ControlSequenceError",
            "ControlStatus",
            "DurableControlLedger",
            "VerifiedControlCommand",
            "monitor_freeze_cause_id",
        ),
        ".control",
    ),
    **dict.fromkeys(
        (
            "monitor_async_performance",
            "monitor_calls",
            "monitor_execution_time",
            "monitor_performance",
        ),
        ".decorators",
    ),
    **dict.fromkeys(
        (
            "DEFAULT_ALERT_RETENTION_SECONDS",
            "DEFAULT_THRESHOLD_STORAGE_POLICY",
            "ScopedThresholdRuleLoop",
            "THRESHOLD_ALERT_ID_PREFIX",
            "ThresholdAlert",
            "ThresholdLateEventError",
            "ThresholdRule",
            "ThresholdRuleCapacityError",
            "ThresholdRuleError",
            "ThresholdRuleStatus",
            "ThresholdRuleStoragePolicy",
        ),
        ".threshold_rules",
    ),
    **dict.fromkeys(
        (
            "MonitorThresholdResourceProvider",
            "THRESHOLD_ALERT_EVENT_TYPE",
            "THRESHOLD_ALERT_SCHEMA",
            "ThresholdRuleConsumerSupervisor",
            "ThresholdServiceConfig",
            "ThresholdServiceError",
            "TrustedThresholdTarget",
            "create_monitor_threshold_resource_provider",
            "parse_threshold_service_config",
        ),
        ".threshold_service",
    ),
    **dict.fromkeys(
        (
            "GATEWAY_MARKET_OBSERVATION_EVENT_TYPE",
            "MONITOR_MARKET_OBSERVATION_SCHEMA",
            "MonitorMarketObservationError",
            "MonitorMarketObservationProjector",
        ),
        ".market_observation",
    ),
    **dict.fromkeys(
        (
            "ElasticsearchClient",
            "ELKIntegration",
            "LogstashHandler",
            "get_elk_integration",
            "setup_elk_integration",
            "shutdown_elk_integration",
        ),
        ".elk",
    ),
    **dict.fromkeys(
        (
            "ExchangeHealthMonitor",
            "ExchangeHealthSummary",
            "HealthCheck",
            "HealthCheckFactory",
            "HealthCheckResult",
            "HealthStatus",
        ),
        ".exchange_health",
    ),
    **dict.fromkeys(
        (
            "EconomicFactReadModel",
            "FactCursorError",
            "FactPage",
            "FactReadError",
            "FactRecord",
            "export_fact_page",
        ),
        ".facts",
    ),
    **dict.fromkeys(
        (
            "GrafanaDashboardBuilder",
            "create_exchange_dashboard",
            "create_system_dashboard",
            "create_trading_dashboard",
            "get_all_dashboard_configs",
            "save_dashboard_to_file",
        ),
        ".grafana",
    ),
    **dict.fromkeys(
        (
            "CONTROL_COMMAND_HMAC_DOMAIN",
            "ControlIssuerPolicy",
            "ControlIssuerPolicyResolver",
            "ControlKeyResolver",
            "ControlScopeGrant",
            "HmacControlCommandVerifier",
            "HmacControlKey",
        ),
        ".ingress",
    ),
    **dict.fromkeys(
        (
            "Counter",
            "Gauge",
            "Histogram",
            "MetricRegistry",
            "PerformanceTimer",
            "counter",
            "gauge",
            "get_registry",
            "histogram",
            "timer",
        ),
        ".metrics",
    ),
    **dict.fromkeys(
        (
            "PrometheusExporter",
            "get_prometheus_exporter",
            "start_prometheus_exporter",
            "stop_prometheus_exporter",
        ),
        ".prometheus",
    ),
    **dict.fromkeys(
        (
            "EVENT_READ_HMAC_DOMAIN",
            "MAX_EVENT_READ_PAGE_SIZE",
            "EventReadAuthenticationError",
            "EventReadCursorError",
            "EventReadError",
            "EventReadItemV1",
            "EventReadPageV1",
            "EventReadReplayError",
            "EventReadRequestV1",
            "ReadOnlyEventService",
            "sign_event_read_request",
            "verify_event_read_page",
        ),
        ".readonly_events",
    ),
    **dict.fromkeys(
        (
            "BusinessMetricsCollector",
            "SystemMetrics",
            "SystemMetricsCollector",
            "get_business_collector",
            "get_system_collector",
        ),
        ".system_metrics",
    ),
    "get_logger": "bt_api_base.logging_factory",
}

__all__ = [
    # Core monitoring
    "MetricsCollector",
    "PerformanceMetrics",
    "get_global_collector",
    "start_global_monitoring",
    "stop_global_monitoring",
    # Durable monitor event and control primitives
    "CheckpointError",
    "DurableOutbox",
    "DurableOutboxConsumer",
    "OutboxConflictError",
    "OutboxDeliveryCallable",
    "OutboxDeliveryError",
    "OutboxError",
    "OutboxEvent",
    "SequencedOutboxEvent",
    "DEFAULT_ALERT_RETENTION_SECONDS",
    "DEFAULT_THRESHOLD_STORAGE_POLICY",
    "ScopedThresholdRuleLoop",
    "THRESHOLD_ALERT_ID_PREFIX",
    "ThresholdAlert",
    "ThresholdLateEventError",
    "ThresholdRule",
    "ThresholdRuleCapacityError",
    "ThresholdRuleError",
    "ThresholdRuleStatus",
    "ThresholdRuleStoragePolicy",
    "MonitorThresholdResourceProvider",
    "THRESHOLD_ALERT_EVENT_TYPE",
    "THRESHOLD_ALERT_SCHEMA",
    "ThresholdRuleConsumerSupervisor",
    "ThresholdServiceConfig",
    "ThresholdServiceError",
    "TrustedThresholdTarget",
    "create_monitor_threshold_resource_provider",
    "parse_threshold_service_config",
    "GATEWAY_MARKET_OBSERVATION_EVENT_TYPE",
    "MONITOR_MARKET_OBSERVATION_SCHEMA",
    "MonitorMarketObservationError",
    "MonitorMarketObservationProjector",
    "EconomicFactReadModel",
    "FactCursorError",
    "FactPage",
    "FactReadError",
    "FactRecord",
    "export_fact_page",
    "EVENT_READ_HMAC_DOMAIN",
    "MAX_EVENT_READ_PAGE_SIZE",
    "EventReadAuthenticationError",
    "EventReadCursorError",
    "EventReadError",
    "EventReadItemV1",
    "EventReadPageV1",
    "EventReadReplayError",
    "EventReadRequestV1",
    "ReadOnlyEventService",
    "sign_event_read_request",
    "verify_event_read_page",
    "ClaimedControlCommand",
    "ControlAction",
    "ControlAuthorizationError",
    "ControlCommandBinding",
    "ControlClaimError",
    "ControlCommand",
    "ControlCommandEnvelope",
    "ControlCommandVerifier",
    "ControlConflictError",
    "ControlIngress",
    "ControlIssuerPolicy",
    "ControlIssuerPolicyResolver",
    "ControlKeyResolver",
    "ControlLedgerError",
    "ControlOwnerOutcome",
    "ControlScopeGrant",
    "ControlSequenceError",
    "ControlStatus",
    "DurableControlLedger",
    "HmacControlCommandVerifier",
    "HmacControlKey",
    "VerifiedControlCommand",
    "CONTROL_COMMAND_HMAC_DOMAIN",
    # Decorators
    "monitor_performance",
    "monitor_execution_time",
    "monitor_calls",
    "monitor_async_performance",
    # Exchange health
    "ExchangeHealthMonitor",
    "HealthStatus",
    "HealthCheck",
    "HealthCheckResult",
    "ExchangeHealthSummary",
    "HealthCheckFactory",
    # Metrics
    "Counter",
    "Gauge",
    "Histogram",
    "MetricRegistry",
    "PerformanceTimer",
    "timer",
    "counter",
    "gauge",
    "histogram",
    "get_registry",
    # System metrics
    "SystemMetricsCollector",
    "BusinessMetricsCollector",
    "SystemMetrics",
    "get_system_collector",
    "get_business_collector",
    # Prometheus
    "PrometheusExporter",
    "start_prometheus_exporter",
    "stop_prometheus_exporter",
    "get_prometheus_exporter",
    # ELK Stack
    "ELKIntegration",
    "ElasticsearchClient",
    "LogstashHandler",
    "setup_elk_integration",
    "get_elk_integration",
    "shutdown_elk_integration",
    # Grafana
    "GrafanaDashboardBuilder",
    "create_trading_dashboard",
    "create_system_dashboard",
    "create_exchange_dashboard",
    "save_dashboard_to_file",
    "get_all_dashboard_configs",
    "get_logger",
]


def __getattr__(name: str) -> Any:
    """Import and cache one explicitly requested public object."""

    module_name = _EXPORT_MODULES.get(name)
    if module_name is None:
        raise AttributeError(f"module {__name__!r} has no attribute {name!r}") from None
    if module_name.startswith("."):
        module = import_module(module_name, __name__)
    else:
        module = import_module(module_name)
    value = getattr(module, name)
    globals()[name] = value
    return value


def __dir__() -> list[str]:
    """Keep lazy public objects discoverable through ``dir()``."""

    return sorted(set(globals()).union(__all__))
