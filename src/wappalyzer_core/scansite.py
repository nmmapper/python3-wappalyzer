import json
import asyncio
import logging
from wappalyzer_core.wappalyzer_driver import WappalyzerDriver,SyncWappalyzerDriver
from wappalyzer_core.analyzer import Wappalyzer
from wappalyzer_core.browser import BrowserOptions
# Assuming these constants point to the correct JSON file paths
from wappalyzer_core.appdata import CATEGORY, TECHNOLOGY

# Configure logging to see cleanup actions
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("ScanSite")

GLOBAL_OPTIONS = BrowserOptions(
    browser_type='webkit',
    headless=True,
)

# Module-level singleton cache
_TECHNOLOGIES_CACHE = None
_CATEGORIES_CACHE = None
_WAPPALYZER_INSTANCE = None
_INIT_LOCK = None  # Instantiated lazily inside the event loop


def get_wappalyzer_data():
    """Returns cached technologies and categories, loading them from disk only once."""
    global _TECHNOLOGIES_CACHE, _CATEGORIES_CACHE
    
    if _TECHNOLOGIES_CACHE is None or _CATEGORIES_CACHE is None:
        try:
            with open(TECHNOLOGY, 'r') as f:
                _TECHNOLOGIES_CACHE = json.load(f)
            with open(CATEGORY, 'r') as f:
                _CATEGORIES_CACHE = json.load(f)
            logger.info("[Wappalyzer] Successfully loaded definition JSONs into process memory.")
        except FileNotFoundError as e:
            logger.error(f"[Wappalyzer] Missing definition files: {e}")
            return None, None
    else:
        logger.info('[Wappalyzer] Successfully loaded definition JSONs FROM cached memory.')
            
    return _TECHNOLOGIES_CACHE, _CATEGORIES_CACHE

async def get_wappalyzer_instance():
    """
    Safely initializes and returns the shared Wappalyzer instance.
    Guarantees thread/coroutine safety using a lazy async lock.
    """
    global _WAPPALYZER_INSTANCE, _INIT_LOCK

    if _WAPPALYZER_INSTANCE is not None:
        return _WAPPALYZER_INSTANCE

    # Create lock lazily inside the running event loop if not yet set
    if _INIT_LOCK is None:
        _INIT_LOCK = asyncio.Lock()

    async with _INIT_LOCK:
        # Double-check pattern to handle concurrent coroutines entering lock
        if _WAPPALYZER_INSTANCE is None:
            technologies, categories = get_wappalyzer_data()
            if technologies is None or categories is None:
                return None

            analyzer = Wappalyzer()
            analyzer.set_technologies(technologies)
            analyzer.set_categories(categories)
            
            _WAPPALYZER_INSTANCE = analyzer
            logger.info("[Wappalyzer] Pre-loaded definitions and initialized shared analyzer instance.")
        else:
            logger.debug('Already initialized wappalyzer instance using it.')
            
    return _WAPPALYZER_INSTANCE


async def scan(domain: str, use_http_only: bool = True):
    """
    Scans a domain for technologies using the shared Wappalyzer singleton.
    """
    # 1. Grab shared analyzer (await async lock)
    #wappalyzer = await get_wappalyzer_instance()
    #if not wappalyzer:
    #    return {}
    technologies, categories = get_wappalyzer_data()
    if technologies is None or categories is None:
        return {}

    wappalyzer = Wappalyzer()
    wappalyzer.set_technologies(technologies)
    wappalyzer.set_categories(categories)
              
    results = []

    try:
        async with WappalyzerDriver(
            analyzer=wappalyzer, 
            browser_options=GLOBAL_OPTIONS, 
            use_http_only=use_http_only
        ) as driver:
            try:
                results = await driver.analyze(domain)
            except Exception as e:
                logger.warning(f"Initial scan failed for {domain}: {e}")
                results = []

    except Exception as e:
        logger.error(f"Unexpected error during scan orchestration for {domain}: {e}")

    # Transform results to name-keyed dictionary
    return {item['name']: item for item in results}


def sync_scan(domain: str, use_http_only: bool = True):
    """
    Scans a domain for technologies.
    Includes fallback from HTTP to Browser if results are empty.
    """
    # 1. Load data
    technologies, categories = get_wappalyzer_data()
    if technologies is None or categories is None:
        return {}

    # 2. Setup Analyzer
    wappalyzer = Wappalyzer()
    wappalyzer.set_technologies(technologies)
    wappalyzer.set_categories(categories)
    
    results = []

    try:
        # Use context manager for automatic cleanup
        with SyncWappalyzerDriver(analyzer=wappalyzer, browser_options=GLOBAL_OPTIONS, use_http_only=use_http_only) as driver:
            try:
                results = driver.analyze_sync(domain)
            except Exception as e:
                logger.info(f"Initial scan failed for {domain}: {e}")
                results = []

    except Exception as e:
        logger.info(f"Unexpected error during scan orchestration: {e}")
    finally:
        pass

    return {item['name']: item for item in results}

