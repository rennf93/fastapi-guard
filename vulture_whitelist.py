# noqa
"""
Vulture whitelist for FastAPI Guard.

This file contains false positive suppressions for vulture.
Add items here that are used but vulture incorrectly reports as unused.
This file is excluded from linting.
"""

import typing

_ = typing


# FastAPI specific - these are used by FastAPI's dependency injection
# and may appear unused to static analysis
app  # type: ignore
middleware  # type: ignore
exception_handler  # type: ignore
on_event  # type: ignore
get  # type: ignore
post  # type: ignore
put  # type: ignore
delete  # type: ignore
patch  # type: ignore
options  # type: ignore
head  # type: ignore

# Pydantic model fields - these are used but may appear unused
Config  # type: ignore
Field  # type: ignore
validator  # type: ignore
root_validator  # type: ignore
model_config  # type: ignore
field_validator  # type: ignore
model_validator  # type: ignore

# Test fixtures, parameters and pytest specific
fixture  # type: ignore
mark  # type: ignore
parametrize  # type: ignore
raises  # type: ignore
warns  # type: ignore
deprecated_call  # type: ignore
approx  # type: ignore
skip  # type: ignore
xfail  # type: ignore
usefixtures  # type: ignore
filterwarnings  # type: ignore
cleanup_ipban_singleton  # type: ignore
cleanup_ipinfo_singleton  # type: ignore
cleanup_singleton  # type: ignore
cleanup_suspatterns_singleton  # type: ignore
mock_hour  # type: ignore
expected_fields  # type: ignore
missing_header  # type: ignore
reset_state  # type: ignore
clean_rate_limiter  # type: ignore
reset_headers_manager  # type: ignore
exc_tb  # type: ignore
exc_type  # type: ignore
exc_val  # type: ignore

# Async context managers and generators
__aenter__  # type: ignore
__aexit__  # type: ignore
__aiter__  # type: ignore
__anext__  # type: ignore
asend  # type: ignore
athrow  # type: ignore
aclose  # type: ignore

# Protocol methods that may be implemented but not directly called
__getitem__  # type: ignore
__setitem__  # type: ignore
__delitem__  # type: ignore
__contains__  # type: ignore
__len__  # type: ignore
__iter__  # type: ignore
__next__  # type: ignore
__reversed__  # type: ignore
__missing__  # type: ignore

# Redis and caching related
redis_client  # type: ignore
cache_key  # type: ignore
cache_prefix  # type: ignore
cache_ttl  # type: ignore

# Security headers and middleware specific
security_headers  # type: ignore
custom_headers  # type: ignore
cors_origins  # type: ignore
trusted_hosts  # type: ignore

# Type hints and typing related
TypeVar  # type: ignore
Generic  # type: ignore
Protocol  # type: ignore
TypedDict  # type: ignore
Literal  # type: ignore
Any  # type: ignore
NoReturn  # type: ignore
ClassVar  # type: ignore

# Logging related
debug  # type: ignore
info  # type: ignore
warning  # type: ignore
error  # type: ignore
critical  # type: ignore
exception  # type: ignore
log  # type: ignore

# Common test helpers and mocks
mock  # type: ignore
patch  # type: ignore
MagicMock  # type: ignore
AsyncMock  # type: ignore
PropertyMock  # type: ignore
call  # type: ignore
call_args  # type: ignore
call_args_list  # type: ignore
called  # type: ignore
call_count  # type: ignore

# FastAPI Guard specific patterns
block_duration  # type: ignore
allowed_hosts  # type: ignore
auto_ban_threshold  # type: ignore
global_rate_limit  # type: ignore
custom_rate_limit_func  # type: ignore
whitelist_mode  # type: ignore
blacklist_mode  # type: ignore
ip_whitelist  # type: ignore
ip_blacklist  # type: ignore
request_id  # type: ignore
attack_detected  # type: ignore
penetration_attempt  # type: ignore
intrusion_attempt  # type: ignore