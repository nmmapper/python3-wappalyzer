"""Pattern parsing and compilation module"""

import re
import regex  
from typing import Any, Dict, List, Optional, Union
from dataclasses import dataclass, field
from enum import Enum

# Set default regex timeout to prevent ReDoS on massive DOM payloads
regex.DEFAULT_TIMEOUT = 2.0

VALID_PYTHON_ESCAPES = set("abfnrtvxcwWsSdDxbBAZEGg1234567890()?*+[]{}|.^$\\")

class ConfidenceLevel(Enum):
    CERTAIN = 100
    HIGH = 90
    MEDIUM = 75
    LOW = 50

@dataclass
class Pattern:
    regex: Union[re.Pattern, regex.Pattern]
    value: str
    confidence: int = 100
    version: str = ""

    def matches(self, text: str) -> Optional[Union[re.Match, regex.Match]]:
        if not text:
            return None
        try:
            return self.regex.search(str(text))
        except Exception:
            return None

class PatternCompiler:
    @staticmethod
    def clean_js_escapes(pattern: str) -> str:
        result = []
        i = 0
        n = len(pattern)
        while i < n:
            if pattern[i] == "\\" and i + 1 < n:
                next_char = pattern[i + 1]
                if next_char == "/":
                    result.append("/")
                    i += 2
                    continue
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
        token_plus = "__escapedPlusToken__"
        token_star = "__escapedStarToken__"
        pattern = pattern.replace(r"\+", token_plus)
        pattern = pattern.replace(r"\*", token_star)
        pattern = re.sub(r"(?<!\{)\+(?!\?)", "{1,250}", pattern)
        pattern = re.sub(r"(?<!\{)\*(?!\?)", "{0,250}", pattern)
        pattern = pattern.replace(token_plus, r"\+")
        pattern = pattern.replace(token_star, r"\*")
        return pattern

    @classmethod
    def compile(cls, pattern_str: str, case_sensitive: bool = False) -> Union[re.Pattern, regex.Pattern]:
        try:
            optimized = cls.clean_js_escapes(pattern_str)
            js_literal_match = re.match(r"^/(.+)/([a-z]*)$", optimized)
            if js_literal_match:
                inner_pat, flags = js_literal_match.groups()
                if "i" in flags:
                    case_sensitive = False
                optimized = inner_pat
            optimized = cls.optimize_quantifiers(optimized)
            flags = 0 if case_sensitive else re.IGNORECASE
            return regex.compile(optimized, flags)
        except (re.error, regex.error) as e:
            raise ValueError(f"Invalid regex pattern: {pattern_str} (compiled as: {optimized})") from e

class PatternParser:
    DELIMITER = r"\;"

    @staticmethod
    def parse(pattern: Union[str, int, Dict, List], case_sensitive: bool = False, is_regex: bool = True) -> Union[Pattern, Dict[str, Pattern], List[Pattern]]:
        if isinstance(pattern, dict):
            return {key: PatternParser.parse(value, case_sensitive, is_regex) for key, value in pattern.items()}
        if isinstance(pattern, list):
            return [PatternParser.parse(item, case_sensitive, is_regex) for item in pattern]
        if isinstance(pattern, (str, int)):
            return PatternParser._parse_single(str(pattern), case_sensitive, is_regex)
        return pattern

    @staticmethod
    def _parse_single(pattern_str: str, case_sensitive: bool = False, is_regex: bool = True) -> Pattern:
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

        return Pattern(regex=compiled_regex, value=value, confidence=confidence, version=version)

class PatternFactory:
    @staticmethod
    def from_raw(patterns: Any, case_sensitive: bool = False, is_regex: bool = True) -> Union[List[Pattern], Dict[str, List[Pattern]]]:
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
            parsed_patterns = [PatternParser.parse(item, case_sensitive, is_regex) for item in value_list]
            parsed[normalized_key] = parsed_patterns
        if list(parsed.keys()) == ['main']:
            return parsed['main']
        return parsed
