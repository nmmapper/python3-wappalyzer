"""Pattern parsing and compilation module"""

import re
import regex  
from typing import Any, Dict, List, Optional, Union
from dataclasses import dataclass, field
from enum import Enum

# Characters recognized as valid escape codes in Python regex
VALID_PYTHON_ESCAPES = set("abfnrtvxcwWsSdDxbBAZEGg1234567890()?*+[]{}|.^$\\")


class ConfidenceLevel(Enum):
    """Confidence levels for pattern matches"""
    CERTAIN = 100
    HIGH = 90
    MEDIUM = 75
    LOW = 50


@dataclass
class Pattern:
    """Represents a single compiled pattern for technology detection"""
    regex: Union[re.Pattern, regex.Pattern]
    value: str
    confidence: int = 100
    version: str = ""

    def matches(self, text: str) -> Optional[Union[re.Match, regex.Match]]:
        """Check if pattern matches text"""
        if not text:
            return None
        try:
            return self.regex.search(str(text))
        except Exception:
            return None


class PatternCompiler:
    """Compiles regex patterns with special syntax handling"""

    @staticmethod
    def clean_js_escapes(pattern: str) -> str:
        """
        Removes invalid Python escape sequences originating from JS regex strings
        (e.g., converts '\k' -> 'k', '\/' -> '/').
        """
        result = []
        i = 0
        n = len(pattern)

        while i < n:
            if pattern[i] == "\\" and i + 1 < n:
                next_char = pattern[i + 1]

                # Convert escaped forward slashes '\/' to plain '/'
                if next_char == "/":
                    result.append("/")
                    i += 2
                    continue

                # Strip backslash for escapes invalid in Python regex
                if next_char not in VALID_PYTHON_ESCAPES:
                    result.append(next_char)
                    i += 2
                    continue
                else:
                    result.append(pattern[i : i + 2])
                    i += 2
                    continue

            result.append(pattern[i])
            i += 1

        return "".join(result)

    @staticmethod
    def optimize_quantifiers(pattern: str) -> str:
        """
        Safely limits unbounded '+' and '*' quantifiers to prevent ReDoS on large text payloads.
        Protects escaped characters like '\+' and '\*' from replacement.
        """
        # Placeholders for escaped tokens
        token_plus = "__escapedPlusToken__"
        token_star = "__escapedStarToken__"

        pattern = pattern.replace(r"\+", token_plus)
        pattern = pattern.replace(r"\*", token_star)

        # Replace unbounded '+' that isn't part of range quantifiers or followed by ?
        pattern = re.sub(r"(?<!\{)\+(?!\?)", "{1,250}", pattern)
        # Replace unbounded '*' that isn't part of range quantifiers or followed by ?
        pattern = re.sub(r"(?<!\{)\*(?!\?)", "{0,250}", pattern)

        # Restore escaped tokens
        pattern = pattern.replace(token_plus, r"\+")
        pattern = pattern.replace(token_star, r"\*")

        return pattern

    @classmethod
    def compile(cls, pattern_str: str, case_sensitive: bool = False) -> Union[re.Pattern, regex.Pattern]:
        """
        Compile a pattern string into a regex object.

        Args:
            pattern_str: The regex pattern string
            case_sensitive: Whether to compile with case sensitivity

        Returns:
            Compiled regex pattern object
        """
        try:
            # 1. Clean invalid JS escapes (e.g. '\k' -> 'k', '\/' -> '/')
            optimized = cls.clean_js_escapes(pattern_str)

            # 2. Extract JS inline flag delimiters: /pattern/i
            js_literal_match = re.match(r"^/(.+)/([a-z]*)$", optimized)
            if js_literal_match:
                inner_pat, flags = js_literal_match.groups()
                if "i" in flags:
                    case_sensitive = False
                optimized = inner_pat

            # 3. Optimize quantifiers for long string payload evaluation
            optimized = cls.optimize_quantifiers(optimized)

            # 4. Set compilation flags
            flags = 0 if case_sensitive else re.IGNORECASE

            return regex.compile(optimized, flags)

        except (re.error, regex.error) as e:
            raise ValueError(f"Invalid regex pattern: {pattern_str} (compiled as: {optimized})") from e


class PatternParser:
    """Parses pattern strings with metadata (confidence, version)"""

    DELIMITER = r"\;"  # Delimiter between value and metadata

    @staticmethod
    def parse(pattern: Union[str, int, Dict, List],
              case_sensitive: bool = False,
              is_regex: bool = True) -> Union[Pattern, Dict[str, Pattern], List[Pattern]]:
        """
        Parse a pattern with optional metadata.
        Format: "regex_pattern\\;version:1.0\\;confidence:100"
        """
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

        parts = pattern_str.split(PatternParser.DELIMITER)
        value = parts[0]

        confidence = 100
        version = ""

        for part in parts[1:]:
            if ':' in part:
                key, val = part.split(':', 1)
                if key == 'confidence':
                    confidence = int(val)
                elif key == 'version':
                    version = val

        if is_regex:
            compiled_regex = PatternCompiler.compile(value, case_sensitive)
        else:
            try:
                flags = 0 if case_sensitive else re.IGNORECASE
                compiled_regex = re.compile(re.escape(value), flags)
            except re.error as e:
                raise ValueError(f"Failed to escape pattern: {value}") from e

        return Pattern(
            regex=compiled_regex,
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
        """
        if patterns is None:
            return []

        if isinstance(patterns, (str, int)):
            patterns = {'main': patterns}
        elif isinstance(patterns, list):
            patterns = {'main': patterns}

        parsed = {}
        for key, value in patterns.items():
            normalized_key = key if case_sensitive else key.lower()
            value_list = value if isinstance(value, list) else [value]

            parsed_patterns = [
                PatternParser.parse(item, case_sensitive, is_regex)
                for item in value_list
            ]

            parsed[normalized_key] = parsed_patterns

        if list(parsed.keys()) == ['main']:
            return parsed['main']

        return parsed
