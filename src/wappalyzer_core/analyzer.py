"""Core Wappalyzer analyzer - Technology detection engine"""

import re
from typing import Any, Dict, List, Optional, Tuple, Union
from dataclasses import dataclass, field
from collections import defaultdict
import inspect
from wappalyzer_core.patterns import Pattern, PatternFactory
import logging

logging.basicConfig(
    level=logging.INFO,
    format="[%(asctime)s] %(levelname)s %(name)s: %(message)s"
)
logger = logging.getLogger("Analyzer")

@dataclass
class Detection:
    """A single technology detection result"""
    technology: Dict[str, Any]
    pattern: Pattern
    match_text: str
    confidence: int
    version: str = ""
    pattern_type: str = ""  # The type of pattern (html, header, etc.)
    pattern_value: str = ""  # The matched value


@dataclass
class ResolvedTechnology:
    """Final resolved technology with aggregated data"""
    name: str
    slug: str
    description: str
    categories: List[int]
    icon: str
    website: str
    pricing: List[str]
    cpe: Optional[str]
    confidence: int
    version: str
    root_path: Optional[str] = None
    last_url: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary"""
        return {
            'name': self.name,
            'slug': self.slug,
            'description': self.description,
            'categories': self.categories,
            'icon': self.icon,
            'website': self.website,
            'pricing': self.pricing,
            'cpe': self.cpe,
            'confidence': self.confidence,
            'version': self.version,
            'root_path': self.root_path,
            'lastUrl': self.last_url,
        }


class Wappalyzer:
    """Core technology detection analyzer"""

    # Map of data types to their analysis methods
    ANALYSIS_RELATIONS = {
        'certIssuer': 'analyzeOneToOne',
        'cookies': 'analyzeManyToMany',
        'css': 'analyzeOneToOne',
        'dns': 'analyzeManyToMany',
        'headers': 'analyzeManyToMany',
        'html': 'analyzeOneToOne',
        'meta': 'analyzeManyToMany',
        'probe': 'analyzeManyToMany',
        'robots': 'analyzeOneToOne',
        'scriptSrc': 'analyzeOneToMany',
        'scripts': 'analyzeOneToOne',
        'text': 'analyzeOneToOne',
        'url': 'analyzeOneToOne',
        'xhr': 'analyzeOneToOne',
        'js': 'analyzeManyToMany',  # JavaScript object chains
    }

    def __init__(self):
        """Initialize Wappalyzer"""
        self.technologies: Dict[str, Dict[str, Any]] = {}
        self.categories: Dict[int, Dict[str, Any]] = {}
        self.requires: List[Dict[str, Any]] = []
        self.category_requires: List[Dict[str, Any]] = []
        self._compiled = False
        self.grouped_data: Dict[str, List[Detection]] = defaultdict(list)
        
    def set_technologies(self, data: Dict[str, Dict[str, Any]]) -> None:
        """
        Load and compile technology definitions.

        Args:
            data: Technology definitions from JSON files
        """
        self.technologies = {}

        for name, tech_data in data.items():
            compiled_tech = self._compile_technology(name, tech_data)
            self.technologies[name] = compiled_tech

        self._compiled = True

    def set_categories(self, data: Dict[int, Dict[str, Any]]) -> None:
        """
        Load category definitions.

        Args:
            data: Category definitions from JSON
        """
        self.categories = {}

        for cat_id_str, cat_data in data.items():
            cat_id = int(cat_id_str)
            self.categories[cat_id] = {
                'id': cat_id,
                'slug': self._slugify(cat_data.get('name', '')),
                **cat_data
            }

        # Sort by priority (higher first)
        self.categories = dict(sorted(
            self.categories.items(),
            key=lambda x: x[1].get('priority', 0),
            reverse=True
        ))

    def analyze(self, items: Dict[str, Any]) -> List[Dict[str, Any]]:
        """
        Analyze collected page data against technology patterns.

        Args:
            items: Dictionary containing page data
                - url: page URL
                - html: HTML content
                - headers: HTTP headers
                - cookies: Cookies
                - meta: Meta tags
                - scriptSrc: Script sources
                - scripts: Script content
                - text: Page text
                - dns: DNS records
                - probe: Probe data
                - etc.

        Returns:
            List of detected technologies with confidence and version
        """
        if not self._compiled:
            raise RuntimeError("Technologies not loaded. Call set_technologies first.")
        
        logger.info("Running analyzer")
        detections: List[Detection] = []
        
        # Analyze each technology against the items
        for tech_name, tech_data in self.technologies.items():
            for data_type, method_name in self.ANALYSIS_RELATIONS.items():
                #if data_type not in items or data_type not in tech_data:
                if data_type in items:# or data_type not in tech_data:
                    #continue

                    # Get the appropriate analysis method
                    method = getattr(self, method_name, None)
                    if method is None:
                        continue

                    # Run analysis
                    type_detections = method(
                        tech_name,
                        tech_data,
                        data_type,
                        items[data_type]
                    )

                    detections.extend(type_detections)
                
        # Resolve and deduplicate detections
        return self.resolve(detections)

    def analyzeOneToOne(self,
                        tech_name: str,
                        tech_data: Dict[str, Any],
                        data_type: str,
                        value: str) -> List[Detection]:
        """
        Analyze one value against multiple patterns (html, url, css, etc.).

        Args:
            tech_name: Technology name
            tech_data: Technology definition
            data_type: Type of data (html, url, etc.)
            value: The value to test

        Returns:
            List of detections if patterns match
        """
        detections = []
        patterns = tech_data.get(data_type, [])
        
        if isinstance(patterns, dict):
            # Handle nested patterns
            for key, pattern_list in patterns.items():
                detections.extend(
                    self._match_patterns(
                        tech_data, tech_name, pattern_list, value, data_type
                    )
                )
        else:
            detections.extend(
                self._match_patterns(
                    tech_data, tech_name, patterns, value, data_type
                )
            )
        
        return detections

    def analyzeOneToMany(self,
                         tech_name: str,
                         tech_data: Dict[str, Any],
                         data_type: str,
                         items: List[str]) -> List[Detection]:
        """
        Analyze array of values against patterns (scriptSrc).

        Args:
            tech_name: Technology name
            tech_data: Technology definition
            data_type: Type of data
            items: List of values to test

        Returns:
            List of detections if patterns match
        """
        detections = []
        patterns = tech_data.get(data_type, [])
        
        for value in items:
            detections.extend(
                self._match_patterns(
                    tech_data, tech_name, patterns, value, data_type
                )
            )

        return detections

    def analyzeManyToMany(self,
                          tech_name: str,
                          tech_data: Dict[str, Any],
                          data_type: str,
                          items: Dict[str, Any]) -> List[Detection]:
        """
        Analyze nested objects with patterns (headers, cookies, meta, dns, js).

        Args:
            tech_name: Technology name
            tech_data: Technology definition
            data_type: Type of data
            items: Dictionary of items to test

        Returns:
            List of detections if patterns match
        """
        detections = []

        # Get patterns, which are organized by key
        type_patterns = tech_data.get(data_type, {})
        if not isinstance(type_patterns, dict):
            return detections

        # Check each key's patterns against corresponding values
        for key, pattern_list in type_patterns.items():
            if key not in items:
                continue

            item_values = items[key]
            # Normalize to list
            if not isinstance(item_values, list):
                item_values = [item_values]

            for value in item_values:
                detections.extend(
                    self._match_patterns(
                        tech_data, tech_name, pattern_list, value, data_type,
                        pattern_value=key
                    )
                )
        
        return detections

    def _match_patterns(self,
                        tech_data: Dict[str, Any],
                        tech_name: str,
                        patterns: List[Pattern],
                        value: str,
                        data_type: str,
                        pattern_value: str = "") -> List[Detection]:
        """
        Match a value against a list of patterns.

        Args:
            tech_data: Technology definition
            tech_name: Technology name
            patterns: List of Pattern objects
            value: Value to match
            data_type: Type of data
            pattern_value: The key/property being tested (for many-to-many)

        Returns:
            List of detections if any patterns match
        """
        detections = []

        if not isinstance(patterns, list):
            patterns = [patterns] if patterns else []

        for pattern in patterns:
            if not isinstance(pattern, Pattern):
                continue

            match = pattern.matches(value)
            if not match:
                continue

            # Pattern matched!
            version = self._extract_version(pattern, match.group(0))

            detection = Detection(
                technology=tech_data,
                pattern=pattern,
                match_text=match.group(0),
                confidence=pattern.confidence,
                version=version,
                pattern_type=data_type,
                pattern_value=pattern_value
            )
            detections.append(detection)

        return detections

    def _extract_version(self, pattern: Pattern, matched_text: str) -> str:
        """
        Extract version from pattern and matched text.

        Pattern version can contain backreferences like \\1, \\2
        that refer to regex capture groups.

        Args:
            pattern: Pattern object with version template
            matched_text: The matched text

        Returns:
            Extracted version string
        """
        if not pattern.version or not matched_text:
            return ""

        try:
            # Try to compile pattern and get groups
            match = pattern.regex.search(matched_text)
            if not match:
                return ""

            version = pattern.version
            groups = match.groups()

            # Replace backreferences (\1, \2, etc.)
            for i, group in enumerate(groups, 1):
                if group:
                    version = version.replace(f'\\{i}', group)
                    version = version.replace(f'${i}', group)

            # Clean up unreferenced groups
            version = re.sub(r'\\[0-9]+', '', version)
            version = re.sub(r'\$[0-9]+', '', version)

            return version.strip()

        except Exception:
            return ""

    def resolve(self, detections: List[Detection]) -> List[Dict[str, Any]]:
        """
        Resolve and deduplicate detections.

        - Combine multiple pattern matches for same technology
        - Aggregate confidence scores
        - Handle implied technologies
        - Handle excluded technologies

        Args:
            detections: List of detection objects

        Returns:
            List of resolved technology results
        """
        if not detections:
            return []
        
        # Group detections by technology name
        grouped: Dict[str, List[Detection]] = defaultdict(list)
        for detection in detections:
           
            try:
                tech_name = detection.technology.get('name')
                self.grouped_data[tech_name].append(detection)
            except AttributeError as e:
                pass
            
        # Resolve each technology
        resolved: Dict[str, ResolvedTechnology] = {}
        
        for tech_name, detections_list in self.grouped_data.items():
            if not detections_list:
                continue

            tech_def = detections_list[0].technology
            confidence = 0
            version = ""
            root_path = None
            last_url = None

            # Aggregate confidence from all detections
            for det in detections_list:
                confidence = min(100, confidence + det.confidence)

                # Extract version if available
                if det.version and not version:
                    version = det.version

            # Build resolved technology
            resolved[tech_name] = ResolvedTechnology(
                name=tech_name,
                slug=self._slugify(tech_name),
                description=tech_def.get('description', ''),
                categories=tech_def.get('categories', []),
                icon=tech_def.get('icon', ''),
                website=tech_def.get('website', ''),
                pricing=tech_def.get('pricing', []),
                cpe=tech_def.get('cpe'),
                confidence=confidence,
                version=version,
                root_path=root_path,
                last_url=last_url,
            )

        # Handle implies (technologies that imply others)
        resolved = self._resolve_implies(resolved)

        # Handle excludes (technologies that exclude others)
        resolved = self._resolve_excludes(resolved)

        # Sort by category priority
        sorted_results = self._sort_by_priority(resolved)
        
        return [tech.to_dict() for tech in sorted_results]

    def _resolve_implies(self, resolved: Dict[str, ResolvedTechnology]
                         ) -> Dict[str, ResolvedTechnology]:
        """
        Handle implied technologies.

        If a technology is detected, its implied technologies are added.

        Args:
            resolved: Dictionary of resolved technologies

        Returns:
            Updated dictionary with implied technologies added
        """
        # TODO: Implement implies logic
        # For now, return as-is
        return resolved

    def _resolve_excludes(self, resolved: Dict[str, ResolvedTechnology]
                          ) -> Dict[str, ResolvedTechnology]:
        """
        Handle excluded technologies.

        If a technology is detected, its excluded technologies are removed.

        Args:
            resolved: Dictionary of resolved technologies

        Returns:
            Updated dictionary with excluded technologies removed
        """
        # TODO: Implement excludes logic
        # For now, return as-is
        return resolved

    def _sort_by_priority(self, resolved: Dict[str, ResolvedTechnology]
                          ) -> List[ResolvedTechnology]:
        """
        Sort technologies by category priority.

        Args:
            resolved: Dictionary of resolved technologies

        Returns:
            Sorted list of technologies
        """
        def get_priority(tech: ResolvedTechnology) -> int:
            """Get highest priority of all categories"""
            if not tech.categories:
                return 0
            priorities = [
                self.categories.get(cat_id, {}).get('priority', 0)
                for cat_id in tech.categories
            ]
            return max(priorities) if priorities else 0

        return sorted(resolved.values(), key=get_priority, reverse=True)

    def _compile_technology(self, tech_name: str,
                            tech_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Compile a technology definition by parsing and compiling patterns.

        Args:
            tech_name: Name of technology
            tech_data: Raw technology definition

        Returns:
            Compiled technology definition with Pattern objects
        """
        compiled = {
            'name': tech_name,
            'description': tech_data.get('description'),
            'categories': tech_data.get('cats', []),
            'icon': tech_data.get('icon'),
            'website': tech_data.get('website'),
            'pricing': tech_data.get('pricing', []),
            'cpe': tech_data.get('cpe'),
            'implies': tech_data.get('implies', []),
            'requires': tech_data.get('requires', []),
            'excludes': tech_data.get('excludes', []),
        }

        # Compile each pattern type
        for pattern_type in self.ANALYSIS_RELATIONS.keys():
            if pattern_type in tech_data:
                raw_patterns = tech_data[pattern_type]
                compiled[pattern_type] = self._compile_patterns(
                    raw_patterns,
                    case_sensitive=(pattern_type in ['css', 'js']),
                )

        return compiled

    def _compile_patterns(self, patterns: Any,
                          case_sensitive: bool = False) -> Union[List[Pattern], Dict]:
        """
        Compile raw pattern data into Pattern objects.

        Args:
            patterns: Raw pattern data (string, list, dict)
            case_sensitive: Whether patterns are case-sensitive

        Returns:
            Compiled pattern structure
        """
        return PatternFactory.from_raw(patterns, case_sensitive, is_regex=True)

    @staticmethod
    def _slugify(text: str) -> str:
        """
        Convert text to URL-safe slug.

        Args:
            text: Text to slugify

        Returns:
            Slugified text
        """
        slug = text.lower()
        slug = re.sub(r'[^a-z0-9-]', '-', slug)
        slug = re.sub(r'-+', '-', slug)
        slug = slug.strip('-')
        return slug
