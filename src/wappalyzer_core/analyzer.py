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
    pattern_type: str = ""
    pattern_value: str = ""

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
        'js': 'analyzeManyToMany',
    }

    def __init__(self):
        self.technologies: Dict[str, Dict[str, Any]] = {}
        self.categories: Dict[int, Dict[str, Any]] = {}
        self.requires: List[Dict[str, Any]] = []
        self.category_requires: List[Dict[str, Any]] = []
        self._compiled = False
        
    def set_technologies(self, data: Dict[str, Dict[str, Any]]) -> None:
        self.technologies = {}
        for name, tech_data in data.items():
            compiled_tech = self._compile_technology(name, tech_data)
            self.technologies[name] = compiled_tech
        self._compiled = True

    def set_categories(self, data: Dict[int, Dict[str, Any]]) -> None:
        self.categories = {}
        for cat_id_str, cat_data in data.items():
            cat_id = int(cat_id_str)
            self.categories[cat_id] = {
                'id': cat_id,
                'slug': self._slugify(cat_data.get('name', '')),
                **cat_data
            }
        self.categories = dict(sorted(
            self.categories.items(),
            key=lambda x: x[1].get('priority', 0),
            reverse=True
        ))

    def analyze(self, items: Dict[str, Any]) -> List[Dict[str, Any]]:
        if not self._compiled:
            raise RuntimeError("Technologies not loaded. Call set_technologies first.")
        
        logger.info("Running analyzer")
        detections: List[Detection] = []
        
        for tech_name, tech_data in self.technologies.items():
            for data_type, method_name in self.ANALYSIS_RELATIONS.items():
                if data_type in items:
                    method = getattr(self, method_name, None)
                    if method is None:
                        continue
                    type_detections = method(
                        tech_name,
                        tech_data,
                        data_type,
                        items[data_type]
                    )
                    detections.extend(type_detections)
                
        return self.resolve(detections)

    def analyzeOneToOne(self, tech_name: str, tech_data: Dict[str, Any], data_type: str, value: str) -> List[Detection]:
        detections = []
        patterns = tech_data.get(data_type, [])
        if isinstance(patterns, dict):
            for key, pattern_list in patterns.items():
                detections.extend(self._match_patterns(tech_data, tech_name, pattern_list, value, data_type))
        else:
            detections.extend(self._match_patterns(tech_data, tech_name, patterns, value, data_type))
        return detections

    def analyzeOneToMany(self, tech_name: str, tech_data: Dict[str, Any], data_type: str, items: List[str]) -> List[Detection]:
        detections = []
        patterns = tech_data.get(data_type, [])
        for value in items:
            detections.extend(self._match_patterns(tech_data, tech_name, patterns, value, data_type))
        return detections

    def analyzeManyToMany(self, tech_name: str, tech_data: Dict[str, Any], data_type: str, items: Dict[str, Any]) -> List[Detection]:
        detections = []
        type_patterns = tech_data.get(data_type, {})
        if not isinstance(type_patterns, dict):
            return detections
        for key, pattern_list in type_patterns.items():
            if key not in items:
                continue
            item_values = items[key]
            if not isinstance(item_values, list):
                item_values = [item_values]
            for value in item_values:
                detections.extend(self._match_patterns(tech_data, tech_name, pattern_list, value, data_type, pattern_value=key))
        return detections

    def _match_patterns(self, tech_data: Dict[str, Any], tech_name: str, patterns: List[Pattern], value: str, data_type: str, pattern_value: str = "") -> List[Detection]:
        detections = []
        if not isinstance(patterns, list):
            patterns = [patterns] if patterns else []
        for pattern in patterns:
            if not isinstance(pattern, Pattern):
                continue
            match = pattern.matches(value)
            if not match:
                continue
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
        if not pattern.version or not matched_text:
            return ""
        try:
            match = pattern.regex.search(matched_text)
            if not match:
                return ""
            version = pattern.version
            groups = match.groups()
            for i, group in enumerate(groups, 1):
                if group:
                    version = version.replace(f'\\{i}', group)
                    version = version.replace(f'${i}', group)
            version = re.sub(r'\\[0-9]+', '', version)
            version = re.sub(r'\$[0-9]+', '', version)
            return version.strip()
        except Exception:
            return ""

    def resolve(self, detections: List[Detection]) -> List[Dict[str, Any]]:
        if not detections:
            return []
        
        # Local state dict resolving the singleton leak
        local_grouped_data: Dict[str, List[Detection]] = defaultdict(list)
        for detection in detections:
            try:
                tech_name = detection.technology.get('name')
                local_grouped_data[tech_name].append(detection)
            except AttributeError:
                pass
            
        resolved: Dict[str, ResolvedTechnology] = {}
        
        for tech_name, detections_list in local_grouped_data.items():
            if not detections_list:
                continue

            tech_def = detections_list[0].technology
            confidence = 0
            version = ""

            for det in detections_list:
                confidence = min(100, confidence + det.confidence)
                if det.version and not version:
                    version = det.version

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
                root_path=None,
                last_url=None,
            )

        resolved = self._resolve_implies(resolved)
        resolved = self._resolve_excludes(resolved)
        sorted_results = self._sort_by_priority(resolved)
        
        return [tech.to_dict() for tech in sorted_results]

    def _resolve_implies(self, resolved: Dict[str, ResolvedTechnology]) -> Dict[str, ResolvedTechnology]:
        return resolved

    def _resolve_excludes(self, resolved: Dict[str, ResolvedTechnology]) -> Dict[str, ResolvedTechnology]:
        return resolved

    def _sort_by_priority(self, resolved: Dict[str, ResolvedTechnology]) -> List[ResolvedTechnology]:
        def get_priority(tech: ResolvedTechnology) -> int:
            if not tech.categories:
                return 0
            priorities = [
                self.categories.get(cat_id, {}).get('priority', 0)
                for cat_id in tech.categories
            ]
            return max(priorities) if priorities else 0
        return sorted(resolved.values(), key=get_priority, reverse=True)

    def _compile_technology(self, tech_name: str, tech_data: Dict[str, Any]) -> Dict[str, Any]:
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
        for pattern_type in self.ANALYSIS_RELATIONS.keys():
            if pattern_type in tech_data:
                raw_patterns = tech_data[pattern_type]
                compiled[pattern_type] = self._compile_patterns(
                    raw_patterns,
                    case_sensitive=(pattern_type in ['css', 'js']),
                )
        return compiled

    def _compile_patterns(self, patterns: Any, case_sensitive: bool = False) -> Union[List[Pattern], Dict]:
        return PatternFactory.from_raw(patterns, case_sensitive, is_regex=True)

    @staticmethod
    def _slugify(text: str) -> str:
        slug = text.lower()
        slug = re.sub(r'[^a-z0-9-]', '-', slug)
        slug = re.sub(r'-+', '-', slug)
        slug = slug.strip('-')
        return slug
