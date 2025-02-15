from guard.sus_patterns import SusPatterns
import pytest
import re


@pytest.mark.asyncio
async def test_add_pattern():
    """
    Test adding a custom pattern to SusPatterns.
    """
    sus_patterns = SusPatterns()
    pattern_to_add = r"new_pattern"
    await sus_patterns.add_pattern(pattern_to_add, custom=True)
    assert pattern_to_add in sus_patterns.custom_patterns


@pytest.mark.asyncio
async def test_remove_pattern():
    """
    Test removing a custom pattern from SusPatterns.
    """
    sus_patterns = SusPatterns()
    pattern_to_remove = r"new_pattern"
    await sus_patterns.add_pattern(pattern_to_remove, custom=True)
    await sus_patterns.remove_pattern(pattern_to_remove, custom=True)
    assert pattern_to_remove not in sus_patterns.custom_patterns


@pytest.mark.asyncio
async def test_get_all_patterns():
    """
    Test retrieving all patterns (default and custom) from SusPatterns.
    """
    sus_patterns = SusPatterns()
    default_patterns = sus_patterns.patterns
    custom_pattern = r"custom_pattern"
    await sus_patterns.add_pattern(custom_pattern, custom=True)
    all_patterns = await sus_patterns.get_all_patterns()
    assert custom_pattern in all_patterns
    assert all(pattern in all_patterns for pattern in default_patterns)


@pytest.mark.asyncio
async def test_invalid_pattern_handling():
    with pytest.raises(re.error):
        await SusPatterns.add_pattern(r"invalid(regex", custom=True)


@pytest.mark.asyncio
async def test_remove_nonexistent_pattern():
    sus_patterns = SusPatterns()
    await sus_patterns.remove_pattern(
        "nonexistent",
        custom=True
    )


def test_singleton_behavior():
    instance1 = SusPatterns()
    instance2 = SusPatterns()
    assert instance1 is instance2
    assert instance1.compiled_patterns is instance2.compiled_patterns
