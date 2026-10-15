"""Monitor's compatibility adapter for shared Gateway telemetry projection."""

from __future__ import annotations

from bt_api_base.market_observation_protocol import (
    GatewaySystemTelemetryProjector,
    SystemTelemetryProjectionError,
)
from bt_api_base.service_protocol import WireEnvelope, WireIdentity, WireScope

GATEWAY_MARKET_OBSERVATION_EVENT_TYPE = "gateway.market_observation"
MONITOR_MARKET_OBSERVATION_SCHEMA = "bt_api.monitor.market_observation.v1"


class MonitorMarketObservationError(SystemTelemetryProjectionError):
    """Monitor-named compatibility error with the shared finite error code."""


class MonitorMarketObservationProjector(GatewaySystemTelemetryProjector):
    """Preserve Monitor's public projection contract over the shared wire API."""

    def __init__(
        self,
        expected_identity: WireIdentity,
        expected_scope: WireScope,
        *,
        system_ref: str,
        process_ref: str,
    ) -> None:
        try:
            super().__init__(
                expected_identity,
                expected_scope,
                system_ref=system_ref,
                process_ref=process_ref,
                event_type=GATEWAY_MARKET_OBSERVATION_EVENT_TYPE,
                observation_schema=MONITOR_MARKET_OBSERVATION_SCHEMA,
            )
        except SystemTelemetryProjectionError as error:
            raise MonitorMarketObservationError(error.code) from None

    def project(self, event: WireEnvelope) -> dict[str, object]:
        """Keep Monitor's historical exception type around shared projection."""

        try:
            return super().project(event)
        except SystemTelemetryProjectionError as error:
            raise MonitorMarketObservationError(error.code) from None


__all__ = [
    "GATEWAY_MARKET_OBSERVATION_EVENT_TYPE",
    "MONITOR_MARKET_OBSERVATION_SCHEMA",
    "MonitorMarketObservationError",
    "MonitorMarketObservationProjector",
]
