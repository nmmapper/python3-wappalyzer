"""Pattern parsing and compilation module"""

import re, regex  
from typing import Any, Dict, List, Optional, Union
from dataclasses import dataclass, field
from enum import Enum


class ConfidenceLevel(Enum):
    """Confidence levels for pattern matches"""
    CERTAIN = 100
    HIGH = 90
    MEDIUM = 75
    LOW = 50


@dataclass
class Pattern:
    """Represents a single compiled pattern for technology detection"""
    regex: re.Pattern
    value: str
    confidence: int = 100
    version: str = ""

    def matches(self, text: str) -> Optional[re.Match]:
        """Check if pattern matches text"""
        if not text:
            return None
        try:
            return self.regex.search(str(text))
        except Exception:
            return None


class PatternCompiler:
    """Compiles regex patterns with special syntax handling"""

    # Special characters that need escaping
    ESCAPE_CHARS = {'/'}

    # Quantifiers optimization for long strings
    QUANTIFIER_LIMITS = {
        '+': '{1,250}',  # one or more -> 1 to 250
        '*': '{0,250}',  # zero or more -> 0 to 250
    }

    @staticmethod
    def compile(pattern_str: str, case_sensitive: bool = False) -> re.Pattern:
        """
        Compile a pattern string into a regex object.

        Special handling:
        - Escape forward slashes
        - Optimize quantifiers for long strings (+, *)
        - Add case-insensitive flag

        Args:
            pattern_str: The regex pattern string
            case_sensitive: Whether to compile with case sensitivity

        Returns:
            Compiled regex pattern object

        Raises:
            ValueError: If regex is invalid
        """
        try:
            # Escape slashes
            optimized = pattern_str.replace('/', '\\/')

            # Protect escaped plus from being replaced
            optimized = optimized.replace('\\+', '__escapedPlus__')

            # Optimize quantifiers
            optimized = optimized.replace('+', '{1,250}')
            optimized = optimized.replace('*', '{0,250}')

            # Restore escaped plus
            optimized = optimized.replace('__escapedPlus__', '\\+')

            # Compile with appropriate flags
            flags = 0 if case_sensitive else re.IGNORECASE
            return regex.compile(optimized, flags)
            #return re.compile(optimized, flags)

        except re.error as e:
            raise ValueError(f"Invalid regex pattern: {pattern_str}") from e


class PatternParser:
    """Parses pattern strings with metadata (confidence, version)"""

    DELIMITER = '\\;'  # Delimiter between value and metadata

    @staticmethod
    def parse(pattern: Union[str, int, Dict, List],
              case_sensitive: bool = False,
              is_regex: bool = True) -> Union[Pattern, Dict[str, Pattern], List[Pattern]]:
        """
        Parse a pattern with optional metadata.

        Format: "regex_pattern\\;version:1.0\\;confidence:100"

        Args:
            pattern: Pattern string or nested structure
            case_sensitive: Case sensitivity for pattern matching
            is_regex: Whether to compile as regex

        Returns:
            Pattern object or dict/list of Pattern objects
        """
        # Handle nested objects recursively
        if isinstance(pattern, dict):
            return {
                key: PatternParser.parse(value, case_sensitive, is_regex)
                for key, value in pattern.items()
            }

        if isinstance(pattern, list):
            return [
                PatternParser.parse(item, case_sensitive, is_regex)
                for item in pattern
            ]

        # Parse single pattern
        if isinstance(pattern, (str, int)):
            return PatternParser._parse_single(
                str(pattern), case_sensitive, is_regex
            )

        return pattern

    @staticmethod
    def _parse_single(pattern_str: str,
                      case_sensitive: bool = False,
                      is_regex: bool = True) -> Pattern:
        """Parse a single pattern string with metadata"""

        # Split by delimiter to extract metadata
        parts = pattern_str.split(PatternParser.DELIMITER)
        value = parts[0]

        # Parse key-value metadata
        confidence = 100
        version = ""

        for part in parts[1:]:
            if ':' in part:
                key, val = part.split(':', 1)
                if key == 'confidence':
                    confidence = int(val)
                elif key == 'version':
                    version = val

        # Compile regex if needed
        if is_regex:
            regex = PatternCompiler.compile(value, case_sensitive)
        else:
            # Non-regex mode: create a literal match pattern
            try:
                regex = re.compile(re.escape(value), re.IGNORECASE)
            except re.error as e:
                raise ValueError(f"Failed to escape pattern: {value}") from e

        return Pattern(
            regex=regex,
            value=value,
            confidence=confidence,
            version=version
        )


class PatternFactory:
    """Factory for creating pattern collections from raw data"""

    @staticmethod
    def from_raw(patterns: Any,
                  case_sensitive: bool = False,
                  is_regex: bool = True) -> Union[List[Pattern], Dict[str, List[Pattern]]]:
        """
        Convert raw pattern data (string, list, dict) into Pattern objects.

        Handles conversion of various input formats:
        - String -> List[Pattern]
        - List -> List[Pattern]
        - Dict -> Dict[str, List[Pattern]]

        Args:
            patterns: Raw pattern data
            case_sensitive: Case sensitivity setting
            is_regex: Whether patterns are regex

        Returns:
            Organized pattern structure
        """
        if patterns is None:
            return []

        # Normalize to dict format for processing
        if isinstance(patterns, (str, int)):
            patterns = {'main': patterns}
        elif isinstance(patterns, list):
            patterns = {'main': patterns}

        # Parse all patterns
        parsed = {}
        for key, value in patterns.items():
            # Normalize key (lowercase unless case-sensitive)
            normalized_key = key if case_sensitive else key.lower()

            # Convert value to list if needed
            value_list = value if isinstance(value, list) else [value]

            # Parse each item
            parsed_patterns = [
                PatternParser.parse(item, case_sensitive, is_regex)
                for item in value_list
            ]

            parsed[normalized_key] = parsed_patterns

        # Return unwrapped main if that's the only key
        if list(parsed.keys()) == ['main']:
            return parsed['main']

        return parsed
