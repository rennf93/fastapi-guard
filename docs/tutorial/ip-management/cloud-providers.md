---

title: Cloud Provider IP Blocking - FastAPI Guard
description: Block requests from major cloud providers like AWS, GCP, and Azure using FastAPI Guard's IP management
keywords: cloud ip blocking, aws blocking, gcp blocking, azure blocking, cloud security
---

Cloud Provider IP Blocking
===========================

FastAPI Guard can automatically detect and block requests from major cloud providers. The IP ranges for these providers are only loaded when cloud blocking is enabled, improving startup performance.

___

Supported Providers
-------------------

Currently supported cloud providers:

- Amazon Web Services (AWS)
- Google Cloud Platform (GCP)
- Microsoft Azure

___

Basic Configuration
-------------------

Enable cloud provider IP blocking:

```python
config = SecurityConfig(
    block_cloud_providers={"AWS", "GCP", "Azure"}
)
```

___

Selective Blocking
------------------

Block specific providers:

```python
config = SecurityConfig(
    block_cloud_providers={"AWS"}  # Only block AWS IPs
)
```

___

IP Range Updates
----------------

Cloud IP ranges are automatically updated daily. You can manually refresh them:

```python
from guard.handlers.cloud_handler import cloud_handler

# Refresh IP ranges
cloud_handler.refresh()
```

___

Custom IP Checking
-------------------

Check if an IP belongs to a cloud provider:

```python
from guard.handlers.cloud_handler import cloud_handler

@app.get("/check-cloud/{ip}")
async def check_cloud_ip(ip: str):
    is_cloud = cloud_handler.is_cloud_ip(
        ip,
        providers={"AWS", "GCP", "Azure"}
    )
    return {"ip": ip, "is_cloud": is_cloud}
```
