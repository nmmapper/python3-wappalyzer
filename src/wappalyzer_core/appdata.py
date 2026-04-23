# wappalyzer_core/appdata.py

from importlib import resources

# For Python 3.9+ (recommended)
try:
    from importlib.resources import files as resources_files
except ImportError:
    # Fallback for Python 3.7-3.8
    from importlib.resources import path as resources_path
    from contextlib import closing

def _get_json_path(filename: str) -> str:
    """Return absolute path to a JSON file inside the wappalyzer_core package."""
    # Modern approach (Python 3.9+)
    if hasattr(resources, 'files'):
        return str(resources_files('wappalyzer_core') / filename)
    # Legacy approach (Python 3.7-3.8)
    with closing(resources_path('wappalyzer_core', filename)) as p:
        return str(p)

CATEGORY = _get_json_path('categories.json')
TECHNOLOGY = _get_json_path('technologies.json')
