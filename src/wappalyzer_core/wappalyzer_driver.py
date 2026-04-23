"""Main driver class - Orchestrates browser automation and analysis"""

import asyncio
import logging
from typing import Dict, Optional, Any, List
from wappalyzer_core import Wappalyzer
from wappalyzer_core.browser import AsyncPlaywrightDriver, SyncHttpOnlyDriver, BrowserOptions,SyncPlaywrightDriver, AsyncHttpOnlyDriver
from wappalyzer_core.site import Site, AnalysisOptions, SiteSync

logging.basicConfig(
    level=logging.INFO,
    format="[%(asctime)s] %(levelname)s %(name)s: %(message)s"
)
logger = logging.getLogger("WappalyzerDriver")

class WappalyzerDriver:
    """
    High-level interface for Wappalyzer.

    Combines browser automation with technology detection.
    """

    def __init__(self,
                 analyzer: Optional[Wappalyzer] = None,
                 browser_options: Optional[BrowserOptions] = None,
                 use_http_only: bool = False):
        """
        Initialize Wappalyzer driver.

        Args:
            analyzer: Wappalyzer core analyzer instance
            browser_options: Browser configuration
            use_http_only: Use HTTP-only driver (no JavaScript execution)
        """
        self.analyzer = analyzer or Wappalyzer()

        if use_http_only:
            self.driver = AsyncHttpOnlyDriver()
            self.use_http_only = True
        else:
            self.driver = AsyncPlaywrightDriver(browser_options)
            self.use_http_only = False

        self._initialized = False

    # =========================
    # Async API (unchanged)
    # =========================
    async def __aenter__(self):
        """Support for 'async with' context manager"""
        await self.init()
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        """Ensures cleanup is called automatically"""
        await self.destroy()
        
    async def init(self) -> None:
        """Initialize the driver"""
        try:
            await self.driver.init()
            self._initialized = True
            logger.info("Wappalyzer driver initialized")
        except Exception as e:
            logger.error(f"Driver initialization failed: {str(e)}")
            raise

    async def destroy(self) -> None:
        """Destroy the driver and cleanup resources"""
        try:
            await self.driver.destroy()
            self._initialized = False
            logger.info("Wappalyzer driver destroyed")
        except Exception as e:
            logger.error(f"Driver cleanup failed: {str(e)}")
            raise

    async def analyze(self,
                      url: str,
                      headers: Optional[Dict[str, str]] = None,
                      options: Optional[AnalysisOptions] = None) -> List[Dict[str, Any]]:
        """
        Analyze a website (async).
        """
        if not self._initialized:
            raise RuntimeError("Driver not initialized. Call init() first.")

        try:
            if options is None:
                options = AnalysisOptions()

            if headers:
                options.headers.update(headers)

            if self.use_http_only:
                return await self._analyze_http_only(url, options)
            else:
                return await self._analyze_with_browser(url, options)

        except Exception as e:
            logger.error(f"Analysis failed: {str(e)}")
            raise

    async def _analyze_http_only(self,
                                 url: str,
                                 options: AnalysisOptions) -> List[Dict[str, Any]]:
        try:
            page_data = await self.driver.fetch(url, options.headers)
            if not page_data:
                return []
            
            logger.info("Got page data continuing to analyze it")
            return self.analyzer.analyze(page_data)

        except Exception as e:
            logger.error(f"HTTP analysis failed: {str(e)}")
            return []

    async def _analyze_with_browser(self,
                                    url: str,
                                    options: AnalysisOptions) -> List[Dict[str, Any]]:
        try:
            site = Site(url, self.driver, self.analyzer, options)
            results = await site.analyze()
            await site.cleanup()
            return results

        except Exception as e:
            logger.error(f"Browser analysis failed: {str(e)}")
            raise

    async def analyze_multiple(self,
                               urls: List[str],
                               concurrent: int = 3,
                               headers: Optional[Dict[str, str]] = None,
                               options: Optional[AnalysisOptions] = None) -> List[List[Dict[str, Any]]]:
        if not self._initialized:
            raise RuntimeError("Driver not initialized. Call init() first.")

        semaphore = asyncio.Semaphore(concurrent)

        async def analyze_with_semaphore(url):
            async with semaphore:
                try:
                    return await self.analyze(url, headers, options)
                except Exception as e:
                    logger.error(f"Failed to analyze {url}: {str(e)}")
                    return []

        return await asyncio.gather(*(analyze_with_semaphore(url) for url in urls))

class SyncWappalyzerDriver:
    """
    High-level interface for Wappalyzer.

    Combines browser automation with technology detection.
    """

    def __init__(self,
                 analyzer: Optional[Wappalyzer] = None,
                 browser_options: Optional[BrowserOptions] = None,
                 use_http_only: bool = False):
        """
        Initialize Wappalyzer driver.

        Args:
            analyzer: Wappalyzer core analyzer instance
            browser_options: Browser configuration
            use_http_only: Use HTTP-only driver (no JavaScript execution)
        """
        self.analyzer = analyzer or Wappalyzer()

        if use_http_only:
            self.driver = AsyncHttpOnlyDriver()
            self.use_http_only = True
        else:
            self.driver = SyncPlaywrightDriver(browser_options)
            self.use_http_only = False

        self._initialized = False
        
    # =========================
    # Sync API (NEW)
    # =========================

    def init_sync(self) -> None:
        """Synchronous wrapper for init()"""
        self.driver.init()

    def destroy_sync(self) -> None:
        """Synchronous wrapper for destroy()"""
        self.driver.destroy()

    def analyze_sync(self,
                     url: str,
                     headers: Optional[Dict[str, str]] = None,
                     options: Optional[AnalysisOptions] = None) -> List[Dict[str, Any]]:
        """
        Analyze a website synchronously.
        """
        if self.use_http_only:
            data = self.driver.fetch(url, headers)
            return self.analyzer.analyze(data)
        else:
            site = SiteSync(url, self.driver, self.analyzer)
            return site.analyze()
