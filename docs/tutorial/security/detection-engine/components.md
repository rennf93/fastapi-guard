# Detection Engine Components

This document provides detailed information about each component of the FastAPI Guard Detection Engine, including their actual implementation, capabilities, and usage.

## Component Overview

The Detection Engine consists of four main components, each initialized conditionally based on configuration:

1. **ContentPreprocessor** - Truncates content while preserving attack patterns
2. **PatternCompiler** - Provides timeout-protected pattern matching
3. **SemanticAnalyzer** - Heuristic-based attack detection
4. **PerformanceMonitor** - Tracks execution metrics

## ContentPreprocessor

Located in `guard/detection_engine/preprocessor.py`

### Purpose

Intelligently truncates content to prevent excessive memory usage while ensuring potential attack patterns are preserved.

### Implementation

```python
class ContentPreprocessor:
    """Intelligent content preprocessing with attack pattern preservation."""
    
    def __init__(self, config: SecurityConfig):
        self.max_length = config.detection_max_content_length
        self.preserve_patterns = config.detection_preserve_attack_patterns
```

### Key Methods

#### `preprocess(content: str) -> str`

Preprocesses content with the following logic:

1. If content length ≤ max_length, returns unchanged
2. If preserve_patterns is False, simple truncation
3. If preserve_patterns is True:
   - Scans for attack patterns in a sliding window
   - Preserves sections containing potential attacks
   - Returns truncated content with preserved attack regions

### Attack Pattern Preservation

The preprocessor looks for indicators like:
- SQL keywords: SELECT, UNION, INSERT, DELETE, etc.
- Script tags and JavaScript events
- Path traversal patterns: ../, ..\
- Command injection indicators
- Common encoding patterns

### Example Usage

```python
preprocessor = ContentPreprocessor(config)
processed = preprocessor.preprocess(long_content)
# Result: Truncated content with attack patterns preserved
```

## PatternCompiler

Located in `guard/detection_engine/compiler.py`

### Purpose

Provides safe pattern compilation and execution with timeout protection against ReDoS attacks.

### Implementation

```python
class PatternCompiler:
    """Pattern compilation with timeout protection."""
    
    def __init__(self, config: SecurityConfig):
        self.timeout = config.detection_compiler_timeout
        self._compiled_cache: dict[str, re.Pattern | None] = {}
```

### Key Methods

#### `compile_pattern(pattern: str) -> re.Pattern | None`

Compiles regex patterns with error handling:
- Caches compiled patterns for performance
- Returns None for invalid patterns
- Logs compilation errors

#### `create_safe_matcher(pattern: str, compiled_pattern: re.Pattern) -> Callable`

Creates a timeout-protected matcher function:

```python
async def safe_matcher(content: str) -> dict[str, Any] | None:
    try:
        match = await asyncio.wait_for(
            asyncio.to_thread(compiled_pattern.search, content),
            timeout=self.timeout
        )
        return {"match": match} if match else None
    except asyncio.TimeoutError:
        return {"timeout": True}
```

### Timeout Protection

- Uses `asyncio.wait_for()` with configurable timeout
- Runs pattern matching in thread pool to prevent blocking
- Returns timeout indicator instead of hanging

## SemanticAnalyzer

Located in `guard/detection_engine/semantic.py`

### Purpose

Provides heuristic-based detection of obfuscated attacks that might bypass regex patterns.

### Implementation

```python
class SemanticAnalyzer:
    """Heuristic-based semantic analysis for attack detection."""
    
    def __init__(self, config: SecurityConfig):
        self.threshold = config.detection_semantic_threshold
        self.token_patterns = self._initialize_patterns()
```

### Key Methods

#### `analyze_content(content: str) -> dict[str, Any]`

Performs multi-stage analysis:

1. **Token Extraction**: Breaks content into meaningful tokens
2. **Pattern Analysis**: Looks for attack-specific patterns
3. **Context Evaluation**: Considers token relationships
4. **Scoring**: Calculates threat probability

### Attack Detection Heuristics

The analyzer detects:

- **SQL Injection**:
  - Keywords: SELECT, UNION, WHERE, OR, AND
  - Operators: =, --, /*
  - Functions: concat(), char()
  
- **XSS Attacks**:
  - Tags: <script>, <img>, <iframe>
  - Events: onerror, onload, onclick
  - JavaScript: eval(), alert()

- **Path Traversal**:
  - Patterns: ../, ..\, %2e%2e
  - File references: /etc/passwd, boot.ini

- **Command Injection**:
  - Operators: ;, |, &, $()
  - Commands: wget, curl, nc

### Scoring System

```python
{
    "score": 0.85,  # Overall threat score (0.0-1.0)
    "attack_types": {
        "sql_injection": 0.9,
        "xss": 0.3,
        "path_traversal": 0.0,
        "command_injection": 0.0
    },
    "confidence": "high",  # low, medium, high
    "detected_patterns": [...]
}
```

## PerformanceMonitor

Located in `guard/detection_engine/monitor.py`

### Purpose

Tracks pattern execution performance to identify bottlenecks and optimize detection.

### Implementation

```python
class PerformanceMonitor:
    """Real-time performance monitoring for detection operations."""
    
    def __init__(self, config: SecurityConfig):
        self.history_size = config.detection_monitor_history_size
        self.slow_threshold = config.detection_slow_pattern_threshold
        self.anomaly_threshold = config.detection_anomaly_threshold
        self.max_patterns = config.detection_max_tracked_patterns
        
        self._metrics: deque[dict] = deque(maxlen=self.history_size)
        self._pattern_stats: dict[str, deque] = {}
```

### Key Methods

#### `record_metric(**kwargs)`

Records execution metrics:
- Pattern identifier
- Execution time
- Match result
- Timeout status
- Context information

#### `get_pattern_stats(pattern: str) -> dict`

Returns statistics for a specific pattern:

```python
{
    "execution_count": 150,
    "average_time": 0.003,
    "max_time": 0.125,
    "min_time": 0.001,
    "timeout_count": 2,
    "match_count": 5
}
```

#### `get_slow_patterns(threshold: float | None) -> list[dict]`

Identifies patterns exceeding the threshold:

```python
[
    {
        "pattern": "complex.*regex.*pattern",
        "average_time": 0.150,
        "execution_count": 100,
        "timeout_rate": 0.05
    }
]
```

#### `detect_anomalies() -> list[dict]`

Uses statistical analysis to find anomalous patterns:
- Calculates mean and standard deviation
- Identifies patterns beyond anomaly threshold
- Returns patterns with unusual behavior

### Memory Management

- Fixed-size deques prevent unbounded growth
- Automatic cleanup of old metrics
- Per-pattern tracking limited by max_patterns

## Component Initialization

Components are created lazily in `SusPatternsManager._ensure_detection_components()`:

```python
def _ensure_detection_components(self) -> None:
    """Initialize detection engine components based on configuration."""
    config = get_current_config()
    
    if config.detection_compiler_timeout > 0 and not self._compiler:
        self._compiler = PatternCompiler(config)
    
    if config.detection_max_content_length > 0 and not self._preprocessor:
        self._preprocessor = ContentPreprocessor(config)
    
    if config.detection_semantic_threshold > 0 and not self._semantic_analyzer:
        self._semantic_analyzer = SemanticAnalyzer(config)
    
    if not self._performance_monitor:
        self._performance_monitor = PerformanceMonitor(config)
```

## Component Interaction

The components work together in the `detect()` method:

1. **Preprocessing**: Content is truncated if needed
2. **Pattern Matching**: Each pattern is executed with timeout protection
3. **Semantic Analysis**: Additional heuristic checks if enabled
4. **Performance Tracking**: All operations are monitored

### Example Flow

```python
async def detect(self, content: str, **kwargs) -> dict:
    # 1. Preprocess if configured
    if self._preprocessor:
        processed = self._preprocessor.preprocess(content)
    else:
        processed = content
    
    # 2. Pattern matching with compiler
    threats = []
    for pattern_str in self.patterns:
        if self._compiler:
            matcher = self._compiler.create_safe_matcher(pattern_str, pattern)
            result = await matcher(processed)
            if result and not result.get("timeout"):
                threats.append({"type": "regex", "pattern": pattern_str})
    
    # 3. Semantic analysis if configured
    if self._semantic_analyzer:
        semantic_result = self._semantic_analyzer.analyze_content(processed)
        if semantic_result["score"] > config.detection_semantic_threshold:
            threats.append({"type": "semantic", **semantic_result})
    
    # 4. Record performance
    if self._performance_monitor:
        await self._performance_monitor.record_metric(
            pattern=pattern_str,
            execution_time=elapsed,
            matched=bool(result)
        )
    
    return {
        "is_threat": len(threats) > 0,
        "threats": threats,
        ...
    }
```

## Error Handling

Each component includes comprehensive error handling:

- **PatternCompiler**: Invalid patterns return None
- **ContentPreprocessor**: Handles encoding errors gracefully
- **SemanticAnalyzer**: Returns low scores for parsing errors
- **PerformanceMonitor**: Continues operation if metrics fail

## Performance Optimization

### Caching

- Compiled patterns are cached in PatternCompiler
- Token patterns are pre-initialized in SemanticAnalyzer

### Async Operations

- Pattern matching runs in thread pool
- Metrics recording is non-blocking

### Memory Bounds

- All collections have size limits
- Old data is automatically evicted

## Configuration Impact

| Component | Required Configuration | Impact When Disabled |
|-----------|----------------------|---------------------|
| ContentPreprocessor | `detection_max_content_length > 0` | No content truncation |
| PatternCompiler | `detection_compiler_timeout > 0` | No timeout protection |
| SemanticAnalyzer | `detection_semantic_threshold > 0` | No heuristic detection |
| PerformanceMonitor | Always created | N/A |

## Best Practices

1. **Enable Timeout Protection**: Always set `detection_compiler_timeout` to prevent ReDoS
2. **Set Content Limits**: Use `detection_max_content_length` to bound memory usage
3. **Monitor Performance**: Review slow patterns regularly
4. **Test Semantic Threshold**: Adjust based on false positive tolerance
5. **Clean Up Patterns**: Remove or optimize slow patterns

## Next Steps

- Learn about [Configuration Options](configuration.md)
- Review [Performance Tuning](performance-tuning.md)
- See [Architecture Overview](architecture.md)
