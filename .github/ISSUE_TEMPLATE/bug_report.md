---
name: Bug report
about: Create a report to help us improve FastAPI Guard
title: '[BUG] '
labels: bug
assignees: ''
---

## Bug Description
A clear and concise description of what the bug is.

## Steps To Reproduce
Steps to reproduce the behavior:
1. Configure FastAPI Guard with '...'
2. Make request to endpoint '....'
3. See error

## Expected Behavior
A clear and concise description of what you expected to happen.

## Actual Behavior
What actually happened, including error messages, stack traces, or logs.

## Environment
- FastAPI Guard version: [e.g. 2.1.0]
- Python version: [e.g. 3.11.10]
- FastAPI version: [e.g. 0.115.0]
- OS: [e.g. Ubuntu 22.04, Windows 11, MacOS 15.4]
- Other relevant dependencies:

## Configuration
```python
# Include your FastAPI Guard configuration here
from fastapi import FastAPI
from guard.middleware import SecurityMiddleware
from guard.models import SecurityConfig

app = FastAPI()

# Your configuration
security_config = SecurityConfig(
    # Include your config here
)

app.add_middleware(SecurityMiddleware, config=security_config)
```

## Additional Context
Add any other context about the problem here. For example:
- Is this happening in production or development?
- Does it happen consistently or intermittently?
- Have you tried any workarounds?