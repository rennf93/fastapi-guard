# guard/core/prompt_injection/__init__.py
from guard.core.prompt_injection.canary_manager import CanaryManager
from guard.core.prompt_injection.context_detector import (
    ContextAwareDetector,
    ContextType,
    UserProfile,
)

# Conditional import for optional semantic detection
try:
    from guard.core.prompt_injection.embedding_detector import EmbeddingDetector
except ImportError:
    EmbeddingDetector = None  # type: ignore
from guard.core.prompt_injection.format_strategies import (
    ByteStringStrategy,
    CodeBlockStrategy,
    FormatStrategy,
    FormatStrategyFactory,
    JSONEscapeStrategy,
    ReprStrategy,
    XMLTagStrategy,
)
from guard.core.prompt_injection.injection_scorer import InjectionScorer
from guard.core.prompt_injection.pattern_detector import PatternDetector

try:
    from guard.core.prompt_injection.transformer_detector import TransformerDetector
except ImportError:
    TransformerDetector = None  # type: ignore
from guard.core.prompt_injection.pattern_library import (
    create_default_pattern_manager,
    get_default_patterns,
)
from guard.core.prompt_injection.pattern_manager import PatternManager
from guard.core.prompt_injection.pattern_tester import (
    PatternTester,
    PatternTestResult,
    TestCase,
)
from guard.core.prompt_injection.pattern_types import InjectionPattern, PatternCategory
from guard.core.prompt_injection.prompt_guard import (
    PromptGuard,
    PromptInjectionAttempt,
)
from guard.core.prompt_injection.semantic_matcher import SemanticMatch, SemanticMatcher
from guard.core.prompt_injection.statistical_detector import StatisticalDetector

__all__ = [
    # Main classes
    "PromptGuard",
    "PromptInjectionAttempt",
    # Pattern detection
    "PatternDetector",
    # Enhanced pattern system
    "InjectionPattern",
    "PatternCategory",
    "PatternManager",
    "get_default_patterns",
    "create_default_pattern_manager",
    # Pattern testing framework
    "PatternTester",
    "PatternTestResult",
    "TestCase",
    # Semantic matching
    "SemanticMatcher",
    "SemanticMatch",
    # Advanced detection layers
    "StatisticalDetector",
    "ContextAwareDetector",
    "ContextType",
    "UserProfile",
    "InjectionScorer",
    # Semantic detection (NEW)
    "EmbeddingDetector",
    "TransformerDetector",
    # Canary system
    "CanaryManager",
    # Format strategies
    "FormatStrategy",
    "FormatStrategyFactory",
    "ReprStrategy",
    "CodeBlockStrategy",
    "ByteStringStrategy",
    "XMLTagStrategy",
    "JSONEscapeStrategy",
]
