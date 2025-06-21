---

title: Authentication Decorators - FastAPI Guard
description: Learn how to use authentication decorators for HTTPS enforcement, auth requirements, and API key validation
keywords: authentication, https, api keys, security headers, authorization decorators
---

Authentication Decorators
=========================

Authentication decorators provide route-level authentication and authorization controls. These decorators help ensure secure communication and proper authentication for sensitive endpoints.

___

HTTPS Enforcement
-----------------

Force secure connections for specific routes:

. Basic HTTPS Requirement
-----------------------

```python
from guard.decorators import SecurityDecorator

guard_deco = SecurityDecorator(config)

@app.post("/api/login")
@guard_deco.require_https()
def login(credentials: dict):
    return {"token": "secure_jwt_token"}
```

. Combined with Global HTTPS
--------------------------

```python
# Global HTTPS enforcement
config = SecurityConfig(enforce_https=True)

# Route-specific override (still enforced due to global setting)
@app.get("/api/public")
@guard_deco.require_https()  # Explicit requirement
def public_endpoint():
    return {"data": "definitely secure"}
```

. HTTPS for Sensitive Operations
-----------------------------

```python
@app.post("/api/payment")
@guard_deco.require_https()
def payment_endpoint(payment_data: dict):
    return {"status": "payment processed securely"}

@app.post("/api/user/password")
@guard_deco.require_https()
def change_password(password_data: dict):
    return {"status": "password updated"}
```

___

Authentication Requirements
---------------------------

Enforce different types of authentication:

. Bearer Token Authentication
--------------------------

```python
@app.get("/api/profile")
@guard_deco.require_auth(type="bearer")
def user_profile():
    return {"profile": "user data"}
```

. Multiple Authentication Types
----------------------------

```python
@app.get("/api/admin")
@guard_deco.require_auth(type="bearer")
def admin_endpoint():
    return {"admin": "data"}

@app.get("/api/service")
@guard_deco.require_auth(type="basic")
def service_endpoint():
    return {"service": "data"}
```

. Combined HTTPS and Auth
----------------------

```python
@app.post("/api/secure-admin")
@guard_deco.require_https()
@guard_deco.require_auth(type="bearer")
def secure_admin():
    return {"data": "doubly secure"}
```

___

API Key Authentication
----------------------

Require API keys for endpoint access:

. Basic API Key Requirement
------------------------

```python
@app.get("/api/key-protected")
@guard_deco.api_key_auth(header_name="X-API-Key")
def api_key_endpoint():
    return {"data": "api key required"}
```

. Custom Header Names
-------------------

```python
@app.get("/api/custom-key")
@guard_deco.api_key_auth(header_name="X-Custom-Auth")
def custom_key_endpoint():
    return {"data": "custom header auth"}

@app.get("/api/service-key")
@guard_deco.api_key_auth(header_name="Authorization-Key")
def service_key_endpoint():
    return {"data": "service authentication"}
```

. Multiple Key Requirements
-------------------------

```python
@app.get("/api/dual-auth")
@guard_deco.api_key_auth(header_name="X-API-Key")
@guard_deco.api_key_auth(header_name="X-Service-Key")
def dual_auth_endpoint():
    return {"data": "dual key authentication"}
```

___

Required Headers
----------------

Enforce specific headers for authentication and security:

. Security Headers
----------------

```python
@app.get("/api/secure")
@guard_deco.require_headers({
    "X-Requested-With": "XMLHttpRequest",
    "X-CSRF-Token": "required"
})
def secure_endpoint():
    return {"data": "csrf protected"}
```

. API Versioning Headers
----------------------

```python
@app.get("/api/v2/data")
@guard_deco.require_headers({
    "Accept": "application/vnd.api+json",
    "API-Version": "2.0"
})
def versioned_endpoint():
    return {"data": "version 2.0", "format": "json-api"}
```

. Client Identification
----------------------

```python
@app.get("/api/client-specific")
@guard_deco.require_headers({
    "X-Client-ID": "required",
    "X-Client-Version": "required",
    "User-Agent": "required"
})
def client_endpoint():
    return {"data": "client identified"}
```

___

Combined Authentication Patterns
--------------------------------

Stack multiple authentication decorators for comprehensive security:

. Maximum Security Endpoint
-------------------------

```python
@app.post("/api/admin/critical")
@guard_deco.require_https()                          # Secure connection
@guard_deco.require_auth(type="bearer")              # Bearer token
@guard_deco.api_key_auth(header_name="X-Admin-Key")  # Admin API key
@guard_deco.require_headers({
    "X-CSRF-Token": "required",                      # CSRF protection
    "X-Request-ID": "required"                       # Request tracking
})
def critical_admin_endpoint():
    return {"status": "critical operation completed"}
```

. Service-to-Service Authentication
---------------------------------

```python
@app.post("/api/service/webhook")
@guard_deco.require_https()
@guard_deco.api_key_auth(header_name="X-Service-Key")
@guard_deco.require_headers({
    "X-Signature": "required",    # Webhook signature
    "Content-Type": "application/json"
})
def webhook_endpoint():
    return {"status": "webhook processed"}
```

. Client Application Authentication
---------------------------------

```python
@app.get("/api/mobile/data")
@guard_deco.require_https()
@guard_deco.require_auth(type="bearer")
@guard_deco.require_headers({
    "X-App-Version": "required",
    "X-Device-ID": "required",
    "Accept": "application/json"
})
def mobile_endpoint():
    return {"data": "mobile app data"}
```

___

Authentication Flow Examples
----------------------------

. Login Endpoint
--------------

```python
@app.post("/auth/login")
@guard_deco.require_https()
@guard_deco.require_headers({
    "Content-Type": "application/json",
    "X-CSRF-Token": "required"
})
def login(credentials: dict):
    # Validate credentials
    return {"token": "jwt_token", "expires": "3600"}
```

. Token Refresh
-------------

```python
@app.post("/auth/refresh")
@guard_deco.require_https()
@guard_deco.require_auth(type="bearer")
@guard_deco.require_headers({
    "X-Refresh-Token": "required"
})
def refresh_token():
    return {"token": "new_jwt_token", "expires": "3600"}
```

. Logout
------

```python
@app.post("/auth/logout")
@guard_deco.require_auth(type="bearer")
@guard_deco.require_headers({
    "X-CSRF-Token": "required"
})
def logout():
    return {"status": "logged out"}
```

___

API Gateway Pattern
-------------------

Different authentication for different API tiers:

. Public API
----------

```python
@app.get("/api/public/status")
@guard_deco.api_key_auth(header_name="X-Public-Key")
def public_status():
    return {"status": "public api active"}
```

. Partner API
-----------

```python
@app.get("/api/partner/data")
@guard_deco.require_https()
@guard_deco.api_key_auth(header_name="X-Partner-Key")
@guard_deco.require_headers({
    "X-Partner-ID": "required"
})
def partner_data():
    return {"data": "partner exclusive"}
```

. Internal API
------------

```python
@app.get("/api/internal/admin")
@guard_deco.require_https()
@guard_deco.require_auth(type="bearer")
@guard_deco.api_key_auth(header_name="X-Internal-Key")
@guard_deco.require_headers({
    "X-Service-Name": "required",
    "X-Request-Context": "required"
})
def internal_admin():
    return {"data": "internal admin access"}
```

___

Error Handling
--------------

Authentication decorators return specific HTTP status codes:

- **400 Bad Request**: Missing required headers
- **401 Unauthorized**: Invalid or missing authentication
- **403 Forbidden**: Valid auth but insufficient permissions
- **301/302 Redirect**: HTTP to HTTPS redirect

. Custom Error Responses
----------------------

```python
config = SecurityConfig(
    custom_error_responses={
        400: "Missing required authentication headers",
        401: "Invalid authentication credentials",
        403: "Insufficient privileges for this operation"
    }
)
```

___

Best Practices
--------------

. Layer Authentication Methods
----------------------------

Use multiple authentication factors for sensitive operations:

```python
# Good: Multiple authentication layers
@guard_deco.require_https()
@guard_deco.require_auth(type="bearer")
@guard_deco.api_key_auth(header_name="X-API-Key")

# Avoid: Single authentication method for sensitive data
# @guard_deco.api_key_auth(header_name="X-API-Key")  # Too weak for sensitive ops
```

. Always Use HTTPS for Authentication
----------------------------------

Never transmit credentials over unencrypted connections:

```python
# Good: HTTPS enforced for login
@guard_deco.require_https()
@guard_deco.require_auth(type="bearer")

# Bad: Authentication without HTTPS
# @guard_deco.require_auth(type="bearer")  # Credentials could be intercepted
```

. Validate Header Content
-----------------------

Don't just check for presence, validate the content:

```python
# The middleware handles presence validation
@guard_deco.require_headers({"X-API-Key": "required"})

# Your application code should validate the actual key value
def validate_api_key(request):
    api_key = request.headers.get("X-API-Key")
    return api_key in valid_keys
```

. Use Appropriate Authentication for Each Endpoint
----------------------------------------------

Match authentication strength to data sensitivity:

```python
# Public data: Light authentication
@guard_deco.api_key_auth(header_name="X-Public-Key")

# User data: Medium authentication
@guard_deco.require_auth(type="bearer")

# Admin data: Heavy authentication
@guard_deco.require_https()
@guard_deco.require_auth(type="bearer")
@guard_deco.api_key_auth(header_name="X-Admin-Key")
```

___

Integration with FastAPI Security
---------------------------------

Combine decorators with FastAPI's built-in security:

```python
from fastapi import Depends, HTTPException
from fastapi.security import HTTPBearer

security = HTTPBearer()

@app.get("/api/integrated")
@guard_deco.require_https()
@guard_deco.require_headers({"X-Client-ID": "required"})
def integrated_endpoint(token: str = Depends(security)):
    # FastAPI handles token extraction
    # Decorators handle additional security
    return {"data": "integrated security"}
```

___

Testing Authentication
----------------------

Test your authentication decorators:

```python
import pytest
from fastapi.testclient import TestClient

def test_https_required():
    # Should redirect HTTP to HTTPS
    response = client.get("/api/secure", base_url="http://testserver")
    assert response.status_code == 301

def test_api_key_required():
    # Should reject without API key
    response = client.get("/api/key-protected")
    assert response.status_code == 400

    # Should accept with valid API key
    response = client.get(
        "/api/key-protected",
        headers={"X-API-Key": "valid-key"}
    )
    assert response.status_code == 200
```

___

Next Steps
----------

Now that you understand authentication decorators, explore other security features:

- **[Access Control Decorators](access-control.md)** - IP and geographic restrictions
- **[Rate Limiting Decorators](rate-limiting.md)** - Request rate controls
- **[Behavioral Analysis](behavioral.md)** - Monitor authentication patterns
- **[Content Filtering](content-filtering.md)** - Request validation

For complete API reference, see the [Authentication API Documentation](../../api/decorators.md#authenticationmixin).
