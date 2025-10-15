# noqa
"""
Vulture whitelist for FastAPI Guard.

This file contains false positive suppressions for vulture.
Add items here that are used but vulture incorrectly reports as unused.
This file is excluded from linting.
"""

import typing  # pragma: no cover

_ = typing  # pragma: no cover


# FastAPI specific - these are used by FastAPI's dependency injection
# and may appear unused to static analysis
app  # type: ignore  # pragma: no cover
middleware  # type: ignore  # pragma: no cover
exception_handler  # type: ignore  # pragma: no cover
on_event  # type: ignore  # pragma: no cover
get  # type: ignore  # pragma: no cover
post  # type: ignore  # pragma: no cover
put  # type: ignore  # pragma: no cover
delete  # type: ignore  # pragma: no cover
patch  # type: ignore  # pragma: no cover
options  # type: ignore  # pragma: no cover
head  # type: ignore  # pragma: no cover

# Pydantic model fields - these are used but may appear unused
Config  # type: ignore  # pragma: no cover
Field  # type: ignore  # pragma: no cover
validator  # type: ignore  # pragma: no cover
root_validator  # type: ignore  # pragma: no cover
model_config  # type: ignore  # pragma: no cover
field_validator  # type: ignore  # pragma: no cover
model_validator  # type: ignore  # pragma: no cover

# Test fixtures, parameters and pytest specific
fixture  # type: ignore  # pragma: no cover
mark  # type: ignore  # pragma: no cover
parametrize  # type: ignore  # pragma: no cover
raises  # type: ignore  # pragma: no cover
warns  # type: ignore  # pragma: no cover
deprecated_call  # type: ignore  # pragma: no cover
approx  # type: ignore  # pragma: no cover
skip  # type: ignore  # pragma: no cover
xfail  # type: ignore  # pragma: no cover
usefixtures  # type: ignore  # pragma: no cover
filterwarnings  # type: ignore  # pragma: no cover
cleanup_ipban_singleton  # type: ignore  # pragma: no cover
cleanup_ipinfo_singleton  # type: ignore  # pragma: no cover
cleanup_singleton  # type: ignore  # pragma: no cover
cleanup_suspatterns_singleton  # type: ignore  # pragma: no cover
mock_hour  # type: ignore  # pragma: no cover
expected_fields  # type: ignore  # pragma: no cover
missing_header  # type: ignore  # pragma: no cover
reset_state  # type: ignore  # pragma: no cover
clean_rate_limiter  # type: ignore  # pragma: no cover
reset_headers_manager  # type: ignore  # pragma: no cover
exc_tb  # type: ignore  # pragma: no cover
exc_type  # type: ignore  # pragma: no cover
exc_val  # type: ignore  # pragma: no cover

# Async context managers and generators
__aenter__  # type: ignore  # pragma: no cover
__aexit__  # type: ignore  # pragma: no cover
__aiter__  # type: ignore  # pragma: no cover
__anext__  # type: ignore  # pragma: no cover
asend  # type: ignore  # pragma: no cover
athrow  # type: ignore  # pragma: no cover
aclose  # type: ignore  # pragma: no cover

# Protocol methods that may be implemented but not directly called
__getitem__  # type: ignore  # pragma: no cover
__setitem__  # type: ignore  # pragma: no cover
__delitem__  # type: ignore  # pragma: no cover
__contains__  # type: ignore  # pragma: no cover
__len__  # type: ignore  # pragma: no cover
__iter__  # type: ignore  # pragma: no cover
__next__  # type: ignore  # pragma: no cover
__reversed__  # type: ignore  # pragma: no cover
__missing__  # type: ignore  # pragma: no cover

# Redis and caching related
redis_client  # type: ignore  # pragma: no cover
cache_key  # type: ignore  # pragma: no cover
cache_prefix  # type: ignore  # pragma: no cover
cache_ttl  # type: ignore  # pragma: no cover

# Security headers and middleware specific
security_headers  # type: ignore  # pragma: no cover
custom_headers  # type: ignore  # pragma: no cover
cors_origins  # type: ignore  # pragma: no cover
trusted_hosts  # type: ignore  # pragma: no cover

# Type hints and typing related
TypeVar  # type: ignore  # pragma: no cover
Generic  # type: ignore  # pragma: no cover
Protocol  # type: ignore  # pragma: no cover
TypedDict  # type: ignore  # pragma: no cover
Literal  # type: ignore  # pragma: no cover
Any  # type: ignore  # pragma: no cover
NoReturn  # type: ignore  # pragma: no cover
ClassVar  # type: ignore  # pragma: no cover

# Logging related
debug  # type: ignore  # pragma: no cover
info  # type: ignore  # pragma: no cover
warning  # type: ignore  # pragma: no cover
error  # type: ignore  # pragma: no cover
critical  # type: ignore  # pragma: no cover
exception  # type: ignore  # pragma: no cover
log  # type: ignore  # pragma: no cover

# Common test helpers and mocks
mock  # type: ignore  # pragma: no cover
patch  # type: ignore  # pragma: no cover
MagicMock  # type: ignore  # pragma: no cover
AsyncMock  # type: ignore  # pragma: no cover
PropertyMock  # type: ignore  # pragma: no cover
call  # type: ignore  # pragma: no cover
call_args  # type: ignore  # pragma: no cover
call_args_list  # type: ignore  # pragma: no cover
called  # type: ignore  # pragma: no cover
call_count  # type: ignore  # pragma: no cover

# FastAPI Guard specific patterns
block_duration  # type: ignore  # pragma: no cover
allowed_hosts  # type: ignore  # pragma: no cover
auto_ban_threshold  # type: ignore  # pragma: no cover
global_rate_limit  # type: ignore  # pragma: no cover
custom_rate_limit_func  # type: ignore  # pragma: no cover
whitelist_mode  # type: ignore  # pragma: no cover
blacklist_mode  # type: ignore  # pragma: no cover
ip_whitelist  # type: ignore  # pragma: no cover
ip_blacklist  # type: ignore  # pragma: no cover
request_id  # type: ignore  # pragma: no cover
attack_detected  # type: ignore  # pragma: no cover
penetration_attempt  # type: ignore  # pragma: no cover
intrusion_attempt  # type: ignore  # pragma: no cover
