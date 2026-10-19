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
    def __init__(self,
                 analyzer: Optional[Wappalyzer] = None,
                 browser_options: Optional[BrowserOptions] = None,
                 use_http_only: bool = False):
        self.analyzer = analyzer or Wappalyzer()

        if use_http_only:
            self.driver = AsyncHttpOnlyDriver(browser_options)
            self.use_http_only = True
        else:
            self.driver = AsyncPlaywrightDriver(browser_options)
            self.use_http_only = False

        self._initialized = False

    async def __aenter__(self):
        await self.init()
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        await self.destroy()
        
    async def init(self) -> None:
        try:
            await self.driver.init()
            self._initialized = True
            logger.info("Wappalyzer driver initialized")
        except Exception as e:
            logger.info(f"Driver initialization failed: {str(e)}")
            raise

    async def destroy(self) -> None:
        try:
            await self.driver.destroy()
            self._initialized = False
            logger.info("Wappalyzer driver destroyed")
        except Exception as e:
            logger.info(f"Driver cleanup failed: {str(e)}") 
            raise

    async def analyze(self,
                      url: str,
                      headers: Optional[Dict[str, str]] = None,
                      options: Optional[AnalysisOptions] = None) -> List[Dict[str, Any]]:
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
            logger.info(f"Analysis failed: {str(e)}")
            raise

    async def _analyze_http_only(self,
                                 url: str,
                                 options: AnalysisOptions) -> List[Dict[str, Any]]:
        try:
            page_data = await self.driver.fetch(url, options.headers)
            if not page_data:
                return []
            
            #logger.info("Got page data continuing to analyze it")
            return self.analyzer.analyze(page_data)

        except Exception as e:
            logger.info(f"HTTP analysis failed: {str(e)}")
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
            logger.info(f"Browser analysis failed: {str(e)}")
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
                    logger.info(f"Failed to analyze {url}: {str(e)}") 
                    return []

        return await asyncio.gather(*(analyze_with_semaphore(url) for url in urls))

class SyncWappalyzerDriver:
    def __init__(self,
                 analyzer: Optional[Wappalyzer] = None,
                 browser_options: Optional[BrowserOptions] = None,
                 use_http_only: bool = False):
        self.analyzer = analyzer or Wappalyzer()

        if use_http_only:
            self.driver = SyncHttpOnlyDriver(browser_options)
            self.use_http_only = True
        else:
            self.driver = SyncPlaywrightDriver(browser_options)
            self.use_http_only = False

        self._initialized = False
    
    def __enter__(self):
        self.init_sync()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.destroy_sync()

    def init_sync(self) -> None:
        self.driver.init()

    def destroy_sync(self) -> None:
        self.driver.destroy()

    def analyze_sync(self,
                     url: str,
                     headers: Optional[Dict[str, str]] = None,
                     options: Optional[AnalysisOptions] = None) -> List[Dict[str, Any]]:
        if self.use_http_only:
            data = self.driver.fetch(url, headers)
            return self.analyzer.analyze(data)
        else:
            site = SiteSync(url, self.driver, self.analyzer)
            return site.analyze()
