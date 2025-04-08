---
name: Feature request
about: Suggest an idea for FastAPI Guard
title: '[FEATURE] '
labels: enhancement
assignees: ''
---

## Is your feature request related to a problem? Please describe.
A clear and concise description of what the problem is. Ex. I'm always facing issues when [...]

## Describe the solution you'd like
A clear and concise description of what you want to happen. Include any API design ideas or examples of how you'd like to use this feature.

## Describe alternatives you've considered
A clear and concise description of any alternative solutions or features you've considered.

## Example Implementation
If possible, provide a pseudocode example of how this feature might be implemented or used:

```python
# Example code showing how you'd like to use this feature
from fastapi import FastAPI
from guard.middleware import SecurityMiddleware
from guard.models import SecurityConfig

app = FastAPI()

# Your feature example here
security_config = SecurityConfig(
    new_feature=SomeConfiguration(...)
)

app.add_middleware(SecurityMiddleware, config=security_config)
```

## Additional context
Add any other context or screenshots about the feature request here:
- How would this benefit the community?
- Are there similar implementations in other libraries that could be referenced?
- Would this require changes to existing APIs?