<p align="center">
    <a href="https://rennf93.github.io/fastapi-guard/latest/">
        <img src="https://raw.githubusercontent.com/rennf93/fastapi-guard/master/docs/assets/fastapi_guard_legend.svg" alt="FastAPI Guard">
    </a>
</p>

<p align="center">
  <a href="https://badge.fury.io/py/fastapi-guard"><img src="https://badge.fury.io/py/fastapi-guard.svg?cache=none" alt="PyPI version"></a>
  <a href="https://opensource.org/licenses/MIT"><img src="https://img.shields.io/badge/License-MIT-yellow.svg" alt="License: MIT"></a>
  <a href="https://github.com/rennf93/fastapi-guard/actions/workflows/ci.yml"><img src="https://github.com/rennf93/fastapi-guard/actions/workflows/ci.yml/badge.svg" alt="CI"></a>
  <a href="https://github.com/rennf93/fastapi-guard/actions/workflows/release.yml"><img src="https://github.com/rennf93/fastapi-guard/actions/workflows/release.yml/badge.svg" alt="Release"></a>
  <a href="https://github.com/rennf93/fastapi-guard/actions/workflows/code-ql.yml"><img src="https://github.com/rennf93/fastapi-guard/actions/workflows/code-ql.yml/badge.svg" alt="CodeQL"></a>
  <a href="https://pepy.tech/project/fastapi-guard"><img src="https://pepy.tech/badge/fastapi-guard" alt="Downloads"></a>
</p>

<p align="center">
  <a href="https://guard-core.com">Website</a> &middot;
  <a href="https://rennf93.github.io/fastapi-guard/latest/">Docs</a> &middot;
  <a href="https://playground.guard-core.com">Playground</a> &middot;
  <a href="https://app.guard-core.com">Dashboard</a> &middot;
  <a href="https://discord.gg/ZW7ZJbjMkK">Discord</a>
</p>

<p align="center">
  Production-ready security middleware for FastAPI.<br>
  IP filtering, rate limiting, signature-based attack-pattern detection, and 20+ per-route security decorators.
</p>

---

## Quick Start

```bash
uv add fastapi-guard        # uv (recommended)
pip install fastapi-guard    # pip
poetry add fastapi-guard     # poetry
```

---

## Example

```python
from fastapi import FastAPI
from guard import SecurityMiddleware, SecurityConfig

app = FastAPI()

config = SecurityConfig(
    enable_rate_limiting=True,
    rate_limit=30,
    rate_limit_window=60,
    enable_ip_banning=True,
    auto_ban_threshold=5,
    auto_ban_duration=86400,
    custom_log_file="security.log",
    rate_limit=100,
    enforce_https=True,
    enable_cors=True,
    cors_allow_origins=["*"],
    cors_allow_methods=["GET", "POST"],
    cors_allow_headers=["*"],
    cors_allow_credentials=True,
    cors_expose_headers=["X-Custom-Header"],
    cors_max_age=600,
    block_cloud_providers={"AWS", "GCP", "Azure"},
)

app.add_middleware(SecurityMiddleware, config=config)
```


---

## Per-Route Security Decorators

Apply security rules at the endpoint level with composable decorators:

```python
from guard import SecurityConfig, SecurityDecorator

config = SecurityConfig()
guard = SecurityDecorator(config)

@app.get("/api/payments")
@guard.require_auth(type="bearer")
@guard.rate_limit(requests=10, window=60)
@guard.block_countries(["CN", "RU"])
@guard.require_https()
async def process_payment():
    return {"status": "ok"}
```

**Available decorator categories:**

- **Access** --- `require_ip`, `block_countries`, `allow_countries`, `block_clouds`, `bypass`
- **Auth** --- `require_https`, `require_auth`, `api_key_auth`, `require_headers`
- **Rate Limiting** --- `rate_limit`, `geo_rate_limit`
- **Content** --- `block_user_agents`, `content_type_filter`, `max_request_size`, `require_referrer`, `custom_validation`
- **Behavioral** --- `usage_monitor`, `return_monitor`, `suspicious_frequency`, `behavior_analysis`
- **Advanced** --- `time_window`, `honeypot_detection`, `suspicious_detection`

[Full decorator reference](https://rennf93.github.io/fastapi-guard/latest/api/decorators/)

---

## Cloud Dashboard

FastAPI Guard has a centralized cloud platform for real-time monitoring and threat analysis across all your applications.

- **[Dashboard](https://app.guard-core.com)** --- real-time security events, threat intelligence, attack pattern analytics
- **[Playground](https://playground.guard-core.com)** --- try every security feature in-browser with real attack data from a live server
- **Dynamic Rules** --- update security configuration from the dashboard without redeploying
- **GDPR Tools** --- consent management, data export, account deletion

Connect your existing setup in 2 minutes:

```bash
uv add guard-agent    # or: pip install guard-agent
```

```python
from collections.abc import AsyncGenerator
from contextlib import asynccontextmanager

from fastapi import FastAPI
from guard import SecurityConfig, SecurityMiddleware
from guard_agent import AgentConfig, guard_agent

security_config = SecurityConfig(
    enable_agent=True,
    agent_api_key="your-api-key",
    agent_endpoint="https://api.guard-core.com/api/v1",
    agent_project_id="your-project-id",
    agent_buffer_size=5000,
    agent_flush_interval=2,
    agent_enable_events=True,
    agent_enable_metrics=True,
    enable_dynamic_rules=True,
    dynamic_rule_interval=60,
)

agent_config = AgentConfig(
    api_key="your-api-key",
    endpoint="https://api.guard-core.com/api/v1",
    project_id="your-project-id",
    buffer_size=5000,
    flush_interval=2,
)

agent = guard_agent(agent_config)


@asynccontextmanager
async def lifespan(_app: FastAPI) -> AsyncGenerator[None]:
    await agent.start()
    yield
    await agent.stop()


app = FastAPI(lifespan=lifespan)
app.add_middleware(SecurityMiddleware, config=security_config)
```

Free tier includes 10,000 events/month --- no credit card required.

> The core library is fully self-contained and MIT licensed. The cloud dashboard is optional.

---

## Ecosystem

FastAPI Guard is built on [guard-core](https://github.com/rennf93/guard-core), a framework-agnostic security engine. The same protection is available across Python, TypeScript, and Rust.

### Python

| Package | Role | PyPI |
|---|---|---|
| [guard-core](https://github.com/rennf93/guard-core) | Framework-agnostic security engine | [![PyPI](https://img.shields.io/pypi/v/guard-core)](https://pypi.org/project/guard-core/) |
| [guard-agent](https://github.com/rennf93/guard-agent) | Telemetry agent | [![PyPI](https://img.shields.io/pypi/v/guard-agent)](https://pypi.org/project/guard-agent/) |
| [fastapi-guard](https://github.com/rennf93/fastapi-guard) | FastAPI / Starlette adapter (this package) | [![PyPI](https://img.shields.io/pypi/v/fastapi-guard)](https://pypi.org/project/fastapi-guard/) |
| [flaskapi-guard](https://github.com/rennf93/flaskapi-guard) | Flask adapter | [![PyPI](https://img.shields.io/pypi/v/flaskapi-guard)](https://pypi.org/project/flaskapi-guard/) |
| [djapi-guard](https://github.com/rennf93/djapi-guard) | Django adapter | [![PyPI](https://img.shields.io/pypi/v/djapi-guard)](https://pypi.org/project/djapi-guard/) |
| [tornadoapi-guard](https://github.com/rennf93/tornadoapi-guard) | Tornado adapter | [![PyPI](https://img.shields.io/pypi/v/tornadoapi-guard)](https://pypi.org/project/tornadoapi-guard/) |

### TypeScript / JavaScript

Published under the [`@guardcore`](https://www.npmjs.com/org/guardcore) npm scope. Source in the [guard-core-ts](https://github.com/rennf93/guard-core-ts) monorepo. **Production-ready.**

| Package | Role | npm |
|---|---|---|
| [@guardcore/core](https://github.com/rennf93/guard-core-ts/tree/master/packages/core) | Core engine | [![npm](https://img.shields.io/npm/v/%40guardcore%2Fcore)](https://www.npmjs.com/package/@guardcore/core) |
| [@guardcore/express](https://github.com/rennf93/guard-core-ts/tree/master/packages/express) | Express adapter | [![npm](https://img.shields.io/npm/v/%40guardcore%2Fexpress)](https://www.npmjs.com/package/@guardcore/express) |
| [@guardcore/nestjs](https://github.com/rennf93/guard-core-ts/tree/master/packages/nestjs) | NestJS adapter | [![npm](https://img.shields.io/npm/v/%40guardcore%2Fnestjs)](https://www.npmjs.com/package/@guardcore/nestjs) |
| [@guardcore/fastify](https://github.com/rennf93/guard-core-ts/tree/master/packages/fastify) | Fastify adapter | [![npm](https://img.shields.io/npm/v/%40guardcore%2Ffastify)](https://www.npmjs.com/package/@guardcore/fastify) |
| [@guardcore/hono](https://github.com/rennf93/guard-core-ts/tree/master/packages/hono) | Hono adapter | [![npm](https://img.shields.io/npm/v/%40guardcore%2Fhono)](https://www.npmjs.com/package/@guardcore/hono) |

### Rust

Published on crates.io. **🚧 Placeholder crates — implementation in progress.**

| Package | Role | crates.io |
|---|---|---|
| [guard-core](https://github.com/rennf93/guard-core-rs) | Core engine | [![crates.io](https://img.shields.io/crates/v/guard-core)](https://crates.io/crates/guard-core) |
| [actix-guard-rs](https://github.com/rennf93/actix-guard-rs) | Actix adapter | [![crates.io](https://img.shields.io/crates/v/actix-guard-rs)](https://crates.io/crates/actix-guard-rs) |
| [axum-guard-rs](https://github.com/rennf93/axum-guard-rs) | Axum adapter | [![crates.io](https://img.shields.io/crates/v/axum-guard-rs)](https://crates.io/crates/axum-guard-rs) |
| [rocket-guard-rs](https://github.com/rennf93/rocket-guard-rs) | Rocket adapter | [![crates.io](https://img.shields.io/crates/v/rocket-guard-rs)](https://crates.io/crates/rocket-guard-rs) |
| [tower-guard-rs](https://github.com/rennf93/tower-guard-rs) | Tower adapter | [![crates.io](https://img.shields.io/crates/v/tower-guard-rs)](https://crates.io/crates/tower-guard-rs) |

---

## Documentation

- [Installation](https://rennf93.github.io/fastapi-guard/latest/installation/)
- [First Steps](https://rennf93.github.io/fastapi-guard/latest/tutorial/first-steps/)
- [Configuration Reference](https://rennf93.github.io/fastapi-guard/latest/tutorial/configuration/security-config/)
- [Decorator Reference](https://rennf93.github.io/fastapi-guard/latest/api/decorators/)
- [API Reference](https://rennf93.github.io/fastapi-guard/latest/api/overview/)
- [Example App](https://rennf93.github.io/fastapi-guard/latest/tutorial/examples/example-app/)
- [Redis Integration](https://rennf93.github.io/fastapi-guard/latest/tutorial/redis-integration/caching/)

---

## Contributing

Contributions are welcome. See [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

New security features (checks, detection patterns, handlers) should be contributed to [guard-core](https://github.com/rennf93/guard-core). This repo covers the FastAPI/Starlette adapter layer.

---

## License

This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.

---

## Author

[Renzo Franceschini](https://github.com/rennf93)
