import warnings

import guard_core.protocols
import pytest
from fastapi import FastAPI

from guard import SecurityConfig
from guard.middleware import SecurityMiddleware

requires_no_inert_warning = pytest.mark.skipif(
    not hasattr(guard_core.protocols, "BoundedResponseBodyReader"),
    reason=(
        "requires guard-core>=3.12.0 "
        "(geo_ip_handler-without-country-rules warning removed)"
    ),
)


class _StubGeoIPHandler:
    @property
    def is_initialized(self) -> bool:
        return False

    async def initialize(self) -> None:
        return

    async def initialize_redis(self, redis_handler: object) -> None:
        return

    async def initialize_agent(self, agent_handler: object) -> None:
        return

    def get_country(self, ip: str) -> str | None:
        return None

    async def refresh(self) -> None:
        return

    def close(self) -> None:
        return


@requires_no_inert_warning
def test_geo_ip_handler_without_country_rules_does_not_warn() -> None:
    with warnings.catch_warnings(record=True) as records:
        warnings.simplefilter("always")
        SecurityConfig(geo_ip_handler=_StubGeoIPHandler())

    inert_warnings = [
        r for r in records if "geo_ip_handler is set but neither" in str(r.message)
    ]
    assert inert_warnings == []


@requires_no_inert_warning
def test_geo_ip_handler_with_country_rules_does_not_warn() -> None:
    with warnings.catch_warnings(record=True) as records:
        warnings.simplefilter("always")
        SecurityConfig(
            geo_ip_handler=_StubGeoIPHandler(), blocked_countries=frozenset({"US"})
        )

    inert_warnings = [r for r in records if "never be consulted" in str(r.message)]
    assert inert_warnings == []


@requires_no_inert_warning
def test_security_middleware_does_not_emit_the_geo_ip_inert_warning() -> None:
    config = SecurityConfig(geo_ip_handler=_StubGeoIPHandler())

    app = FastAPI()
    with warnings.catch_warnings(record=True) as records:
        warnings.simplefilter("always")
        SecurityMiddleware(app, config=config)

    inert_warnings = [r for r in records if "never be consulted" in str(r.message)]
    assert inert_warnings == []
