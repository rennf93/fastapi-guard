# Route Resolution and Global Behavior Rules

## route_resolution_strict

`route_resolution_strict` (`bool`, default `False`) controls what happens when the middleware cannot resolve the request to a FastAPI route.

`False` (default): the pipeline runs with no per-route config. Undecorated routes and unrouted paths pass through. This is correct when routes without decorators carry no per-route checks.

`True`: the request is blocked when the route cannot be resolved. Use this when every request must be attributable to a known route so a resolution failure cannot silently skip per-route checks.

```python
from guard import SecurityConfig

config = SecurityConfig(route_resolution_strict=True)
```

Trade-off: with `True`, requests to paths the app does not serve turn into 500s instead of 404s. Only enable it when you want unresolved routes treated as failures.

## global_behavior_rules

`global_behavior_rules` (`list[BehaviorRuleConfig]`, default `[]`) applies behavior rules to every route, in addition to any decorator-specified rules. Useful for global 404 watchers and request-volume thresholds.

```python
from guard import BehaviorRule, SecurityConfig

config = SecurityConfig(
    global_behavior_rules=[
        BehaviorRule(action="log", reason="global_404_watch"),
    ],
)
```

`BehaviorRule` fields:

* `action` — what to do when the rule fires (`log`, `block`, etc.).
* `reason` — short label attached to the event/log entry, used for filtering in the dashboard.

Rules from decorators are merged with `global_behavior_rules` at request time; global rules do not override decorator rules, they run alongside them.

## Passive mode interaction

With `passive_mode=True`, any rule whose `action` would block instead only logs. This lets you trial `global_behavior_rules` and `route_resolution_strict=True` against production traffic without dropping legitimate requests.