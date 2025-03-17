from fastapi import FastAPI, Request
from guard.middleware import SecurityMiddleware
from guard.models import SecurityConfig
import logging
import os


logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
)
logger = logging.getLogger(__name__)


app = FastAPI(title="FastAPI Guard Test App")


IPINFO_TOKEN = os.getenv("IPINFO_TOKEN")


# TODO: Adjust the following config as per your needs.
config = SecurityConfig(
    # Whitelist/Blacklist
    whitelist=["127.0.0.1/32", "127.0.0.1"],
    blacklist=["192.168.1.100/32", "10.0.0.100/32"],

    # Rate Limiting
    rate_limit=15,
    rate_limit_window=60,

    # Auto-ban Configuration
    enable_ip_banning=True,
    enable_penetration_detection=True,
    auto_ban_threshold=5,
    auto_ban_duration=300,

    # Excluded Paths (expanded for testing)
    exclude_paths=[
        '/docs',
        '/redoc',
        '/openapi.json',
        '/openapi.yaml',
        '/favicon.ico',
        '/static'
    ],

    # User Agent settings
    blocked_user_agents=[
        'badbot',
        'malicious-crawler'
    ],

    # IPInfo integration
    ipinfo_token=IPINFO_TOKEN,
    blocked_countries=["CN", "RU"],

    # Redis integration
    # NOTE: enable_redis=True by default
    redis_url="redis://localhost:6379",
    redis_prefix="fastapi_guard",
)
# Add the middleware to the app
app.add_middleware(SecurityMiddleware, config=config)


# Test endpoints
@app.get("/")
async def root():
    return {"message": "Hello World"}

@app.get("/health")
async def health():
    return {"status": "healthy"}

@app.get("/whitelist-test")
async def test_whitelist():
    return {"message": "If you see this, you're whitelisted!"}

@app.get("/blacklist-test")
async def test_blacklist():
    return {"message": "If you see this, you're not blacklisted!"}

@app.get("/rate-limit-test")
async def test_rate_limit():
    return {"message": "Rate limit test"}

@app.get("/ban-test")
async def test_ban():
    return {"message": "Ban test"}

@app.get("/test")
async def test_endpoint(
    input: str = None,
    query: str = None,
    path: str = None,
    cmd: str = None
):
    return {"message": "Test endpoint", "input": input}

@app.get("/protected")
async def protected_endpoint():
    return {"message": "Protected endpoint"}

@app.get("/ip")
async def get_ip(request: Request):
    return {"ip": request.client.host}


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)