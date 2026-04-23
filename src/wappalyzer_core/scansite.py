import json
import asyncio
import logging
from wappalyzer_core.wappalyzer_driver import WappalyzerDriver
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

async def scan(domain: str, use_http_only: bool = True):
    """
    Scans a domain for technologies.
    Includes fallback from HTTP to Browser if results are empty.
    """
    # 1. Load data
    try:
        with open(TECHNOLOGY, 'r') as f:
            technologies = json.load(f)
        with open(CATEGORY, 'r') as f:
            categories = json.load(f)
    except FileNotFoundError as e:
        logger.error(f"Missing definition files: {e}")
        return {}

    # 2. Setup Analyzer
    wappalyzer = Wappalyzer()
    wappalyzer.set_technologies(technologies)
    wappalyzer.set_categories(categories)
    
    results = []

    try:
        # Use context manager for automatic cleanup
        async with WappalyzerDriver(analyzer=wappalyzer, browser_options=GLOBAL_OPTIONS, use_http_only=use_http_only) as driver:
            try:
                results = await driver.analyze(domain)
            except Exception as e:
                logger.warning(f"Initial scan failed for {domain}: {e}")
                results = []

        # 3. Fallback Logic: If HTTP-only failed/was empty and we started with it, try full Browser
        #if not results and use_http_only:
        #    logger.info(f"No results with HTTP-only for {domain}. Retrying with full browser...")
        #    async with WappalyzerDriver(analyzer=wappalyzer, browser_options=GLOBAL_OPTIONS, use_http_only=False) as browser_driver:
        #        try:
        #            results = await browser_driver.analyze(domain)
        #        except Exception as e:
        #            logger.error(f"Browser fallback failed for {domain}: {e}")
       #             results = []

    except Exception as e:
        logger.error(f"Unexpected error during scan orchestration: {e}")
    finally:
        # The 'async with' blocks above handle destroy() automatically, 
        # but this block ensures we return something valid even on crash.
        pass

    # Transform results to name-keyed dictionary
    return {item['name']: item for item in results}

#async def main():
#    target = "https://www.nmmapper.com"
##    logger.info(f"Starting scan for {target}")
    
#    results = await scan(target, use_http_only=True)
#    
#    if results:
#        print(json.dumps(results, indent=4))
#    else:
#        print(f"No technologies detected or domain unreachable for {target}")

#if __name__ == "__main__":
#    try:
#        asyncio.run(main())
#    except KeyboardInterrupt:
#        pass
