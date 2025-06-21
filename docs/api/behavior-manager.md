---

title: Behavior Manager API - FastAPI Guard
description: API reference for managing behavioral analysis and monitoring through decorators
keywords: behavior manager, fastapi guard, behavioral analysis, monitoring, automated actions
---

Behavior Manager
=================

The Behavior Manager handles behavioral analysis and monitoring for FastAPI Guard, providing advanced detection capabilities for suspicious usage patterns and automated response actions.

___

Overview
--------

The Behavior Manager system consists of:

- **BehaviorTracker**: Main tracking and analysis engine
- **BehaviorRule**: Rule definition for behavioral analysis
- **Integration**: Seamless integration with decorators and middleware

___

BehaviorTracker
---------------

::: guard.handlers.behavior_handler.BehaviorTracker

The main class responsible for tracking and analyzing user behavior patterns.

. Key Features
--------------

- **Endpoint Usage Tracking**: Monitor how frequently IPs access specific endpoints
- **Return Pattern Analysis**: Detect when IPs receive specific response patterns too often
- **Frequency Detection**: Identify suspiciously high request frequencies
- **Automated Actions**: Apply bans, logs, alerts, or throttling based on rules

. Example Usage
---------------

```python
from guard.handlers.behavior_handler import BehaviorTracker, BehaviorRule

# Create tracker
tracker = BehaviorTracker(config)

# Define rules
usage_rule = BehaviorRule(
    rule_type="usage",
    threshold=10,
    window=3600,
    action="ban"
)

return_rule = BehaviorRule(
    rule_type="return_pattern",
    threshold=3,
    pattern="win",
    window=86400,
    action="alert"
)

# Track usage
await tracker.track_endpoint_usage(endpoint_id, client_ip, usage_rule)

# Track return patterns
await tracker.track_return_pattern(endpoint_id, client_ip, response, return_rule)
```

___

BehaviorRule
------------

::: guard.handlers.behavior_handler.BehaviorRule

Configuration class that defines behavioral analysis rules.

. Rule Types
------------

- **usage**: Monitor endpoint usage frequency
- **return_pattern**: Analyze response patterns
- **frequency**: Detect suspicious request frequencies

. Pattern Formats
-----------------

For `return_pattern` rules, the following pattern formats are supported:

- **Simple string**: `"win"`, `"success"`, `"rare_item"`
- **JSON path**: `"json:result.status==win"`
- **Regex**: `"regex:win|victory|success"`
- **Status code**: `"status:200"`

. Actions
---------

- **ban**: Ban the IP address
- **log**: Log the incident
- **alert**: Send an alert notification
- **throttle**: Apply rate limiting

. Example Rules
---------------

```python
# Usage monitoring
usage_rule = BehaviorRule(
    rule_type="usage",
    threshold=50,
    window=3600,
    action="ban"
)

# Return pattern monitoring
win_rule = BehaviorRule(
    rule_type="return_pattern",
    threshold=3,
    pattern="win",
    window=86400,
    action="ban"
)

# Frequency detection
freq_rule = BehaviorRule(
    rule_type="frequency",
    threshold=30,  # 30 requests
    window=300,    # in 5 minutes
    action="alert"
)
```

___

Integration with Decorators
----------------------------

The Behavior Manager integrates seamlessly with the decorator system:

```python
from guard.decorators import SecurityDecorator

guard_deco = SecurityDecorator(config)

@app.get("/api/rewards")
@guard_deco.usage_monitor(max_calls=10, window=3600, action="ban")
@guard_deco.return_monitor("rare_item", max_occurrences=3, window=86400, action="alert")
def rewards_endpoint():
    return {"reward": "rare_item", "value": 1000}
```

___

Redis Integration
-----------------

The Behavior Manager supports Redis for distributed tracking:

```python
# Initialize with Redis
await tracker.initialize_redis(redis_handler)

# All tracking operations will use Redis for storage
# This enables behavior tracking across multiple instances
```

___

Advanced Usage
--------------

. Custom Pattern Matching
--------------------------

```python
# JSON path pattern
json_rule = BehaviorRule(
    rule_type="return_pattern",
    threshold=5,
    pattern="json:result.reward.rarity==legendary",
    window=86400,
    action="ban"
)

# Regex pattern
regex_rule = BehaviorRule(
    rule_type="return_pattern",
    threshold=10,
    pattern="regex:(win|victory|success)",
    window=3600,
    action="alert"
)

# Status code pattern
status_rule = BehaviorRule(
    rule_type="return_pattern",
    threshold=100,
    pattern="status:200",
    window=3600,
    action="log"
)
```

. Multiple Rule Analysis
------------------------

```python
# Apply multiple rules to an endpoint
rules = [
    BehaviorRule("usage", threshold=20, window=3600, action="ban"),
    BehaviorRule("return_pattern", threshold=5, pattern="win", window=86400, action="alert"),
    BehaviorRule("frequency", threshold=60, window=300, action="throttle")
]

@guard_deco.behavior_analysis(rules)
def complex_endpoint():
    return {"data": "complex"}
```

___

Best Practices
--------------

. Set Appropriate Thresholds
----------------------------

Match thresholds to expected legitimate usage:

```python
# High-value endpoint - strict limits
@guard_deco.usage_monitor(max_calls=5, window=3600, action="ban")

# Regular endpoint - moderate limits
@guard_deco.usage_monitor(max_calls=50, window=3600, action="alert")
```

. Use Graduated Responses
-------------------------

Start with logging, then alerts, then bans:

```python
# First violation - log
BehaviorRule("usage", threshold=10, window=3600, action="log")

# Second violation - alert
BehaviorRule("usage", threshold=20, window=3600, action="alert")

# Third violation - ban
BehaviorRule("usage", threshold=30, window=3600, action="ban")
```

. Monitor Return Patterns Carefully
-----------------------------------

Focus on patterns that indicate abuse:

```python
# Gaming/gambling endpoints
@guard_deco.return_monitor("jackpot", max_occurrences=2, window=86400, action="ban")

# Reward systems
@guard_deco.return_monitor("rare_item", max_occurrences=3, window=86400, action="alert")

# Success patterns
@guard_deco.return_monitor("regex:success|win|victory", max_occurrences=10, window=3600, action="log")
```

___

Error Handling
--------------

The Behavior Manager handles errors gracefully:

- **Redis Connection Issues**: Falls back to in-memory tracking
- **Pattern Matching Errors**: Logs errors and continues processing
- **Action Failures**: Logs failures but doesn't interrupt request flow

___

Monitoring and Debugging
------------------------

Enable detailed logging for behavioral analysis:

```python
config = SecurityConfig(
    log_suspicious_level="DEBUG",
    log_request_level="INFO"
)

# Logs will include:
# - Behavioral rule violations
# - Pattern matching results
# - Action execution results
```

___

Performance Considerations
--------------------------

- **Redis Usage**: Reduces memory usage and enables distributed tracking
- **Pattern Complexity**: Simple string patterns are fastest, regex patterns are slowest
- **Rule Count**: More rules per endpoint increase processing time
- **Window Sizes**: Larger windows require more memory for tracking

___

See Also
--------

- [Behavioral Decorators Tutorial](../tutorial/decorators/behavioral.md) - Learn how to use behavioral decorators
- [Security Decorators Overview](../tutorial/decorators/overview.md) - Complete decorator system overview
- [Redis Integration](../tutorial/redis-integration/caching.md) - Redis setup and configuration
