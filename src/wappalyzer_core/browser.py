"""Browser automation layer using Playwright - Fixed and Enhanced"""

import asyncio
import logging
import re
from typing import Dict, Optional, Any, List, Union
from dataclasses import dataclass, field
from enum import Enum
from bs4 import BeautifulSoup

try:
    from playwright.async_api import async_playwright, Browser as AsyncBrowser, BrowserContext as AsyncContext
    from playwright.sync_api import sync_playwright, Browser as SyncBrowser, BrowserContext as SyncContext
except ImportError:
    raise ImportError("Playwright is required. Install it with: pip install playwright")

import requests
import aiohttp

logging.basicConfig(level=logging.INFO, format="[%(asctime)s] %(levelname)s %(name)s: %(message)s")
logger = logging.getLogger("Browser")

class BrowserType(Enum):
    CHROMIUM = "chromium"
    FIREFOX = "firefox"
    WEBKIT = "webkit"

@dataclass
class BrowserOptions:
    browser_type: Union[BrowserType, str] = BrowserType.CHROMIUM
    headless: bool = True
    proxy: Optional[str] = None
    timeout: int = 30000
    debug: bool = False
    extra_args: List[str] = field(default_factory=list)

    def __post_init__(self):
        if isinstance(self.browser_type, str):
            self.browser_type = BrowserType(self.browser_type.lower())

    def to_launch_args(self) -> Dict[str, Any]:
        args = {"headless": self.headless}
        if self.proxy: 
            args["proxy"] = {"server": self.proxy}
        if self.extra_args: 
            args["args"] = self.extra_args
        return args

def _parse_html_common(html: str, url: str) -> Dict[str, Any]:
    """Helper to extract common Wappalyzer signals from HTML"""
    soup = BeautifulSoup(html, 'html.parser')
    
    # Extract Meta Tags
    meta = {}
    for t in soup.find_all('meta'):
        name = t.get('name') or t.get('property')
        content = t.get('content')
        if name and content:
            if name not in meta: meta[name] = []
            meta[name].append(content)
            
    # Extract Script Sources
    script_src = [t.get('src') for t in soup.find_all('script') if t.get('src')]
    
    # Extract Inline Scripts (for pattern matching)
    scripts = [t.string for t in soup.find_all('script') if t.string]
    
    return {
        'url': url,
        'html': html,
        'meta': meta,
        'scriptSrc': script_src,
        'scripts': scripts,
        'text': soup.get_text(separator=' ', strip=True)
    }

# --- ASYNC LAYERS ---

class AsyncPlaywrightDriver:
    """Async Browser driver using Playwright"""
    def __init__(self, options: Optional[BrowserOptions] = None):
        self.options = options or BrowserOptions()
        self.browser: Optional[AsyncBrowser] = None
        self.context: Optional[AsyncContext] = None
        self.playwright_mgr = None
        self._destroyed = False

    async def __aenter__(self):
        await self.init()
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        await self.destroy()

    async def init(self) -> None:
        self.playwright_mgr = await async_playwright().start()
        launcher = getattr(self.playwright_mgr, self.options.browser_type.value)
        self.browser = await launcher.launch(**self.options.to_launch_args())
        self.context = await self.browser.new_context(user_agent="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36")

    async def new_page(self):
        """
        Create a new browser page/tab.

        Returns:
            Playwright Page instance

        Raises:
            RuntimeError: If browser not initialized or context creation fails
        """
        if not self.context:
            raise RuntimeError("Browser context not initialized. Call init() first.")

        try:
            page = await self.context.new_page()

            # Set default navigation timeout
            page.set_default_timeout(self.options.timeout)
            page.set_default_navigation_timeout(self.options.timeout)

            return page

        except Exception as e:
            logger.error(f"Failed to create new page: {str(e)}")
            raise

    async def fetch(self, url: str, headers: Optional[Dict] = None) -> Dict[str, Any]:
        """Navigates to URL and extracts all Wappalyzer-relevant data"""
        if not self.context: await self.init()
        
        page = await self.new_page()
        if headers: await page.set_extra_http_headers(headers)
        
        try:
            response = await page.goto(url, timeout=self.options.timeout, wait_until="networkidle")
            
            # Basic page data
            html = await page.content()
            current_url = page.url
            status = response.status if response else 0
            
            # Wappalyzer specific data points
            headers_dict = response.headers if response else {}
            cookies_list = await self.context.cookies(current_url)
            cookies = {c['name']: c['value'] for c in cookies_list}
            
            data = _parse_html_common(html, current_url)
            data.update({
                'status': status,
                'headers': {k.lower(): v for k, v in headers_dict.items()},
                'cookies': cookies,
            })
            
            return data
        finally:
            await page.close()

    async def destroy(self) -> None:
        if self._destroyed: return
        if self.context: await self.context.close()
        if self.browser: await self.browser.close()
        if self.playwright_mgr: await self.playwright_mgr.stop()
        self._destroyed = True

class AsyncHttpOnlyDriver:
    """Non-blocking HTTP driver using aiohttp"""
    def __init__(self):
        self._session: Optional[aiohttp.ClientSession] = None

    async def __aenter__(self):
        await self.init()
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        await self.destroy()

    async def init(self) -> None:
        if not self._session:
            self._session = aiohttp.ClientSession(headers={"User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/147.0.0.0 Safari/537.36"})

    async def fetch(self, url: str, headers: Optional[Dict] = None) -> Dict[str, Any]:
        if not self._session: await self.init()
        async with self._session.get(url, headers=headers, timeout=aiohttp.ClientTimeout(total=30)) as resp:
            html = await resp.text()
            data = _parse_html_common(html, str(resp.url))
            data.update({
                'status': resp.status,
                'headers': {k.lower(): v for k, v in resp.headers.items()},
                'cookies': {k: v.value for k, v in resp.cookies.items()}
            })
            return data

    async def destroy(self) -> None:
        if self._session:
            await self._session.close()
            self._session = None

# --- SYNC LAYERS ---

class SyncPlaywrightDriver:
    """Blocking Browser driver using Playwright"""
    def __init__(self, options: Optional[BrowserOptions] = None):
        self.options = options or BrowserOptions()
        self.browser: Optional[SyncBrowser] = None
        self.context: Optional[SyncContext] = None
        self.playwright_mgr = None

    def __enter__(self):
        self.init()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.destroy()

    def init(self) -> None:
        self.playwright_mgr = sync_playwright().start()
        launcher = getattr(self.playwright_mgr, self.options.browser_type.value)
        self.browser = launcher.launch(**self.options.to_launch_args())
        self.context = self.browser.new_context()

    def new_page(self):
        """
        Create a new browser page/tab (Sync).

        Returns:
            Playwright Page instance
        """
        if not self.context:
            raise RuntimeError("Browser context not initialized. Call init() first.")

        try:
            page = self.context.new_page()

            # Set default navigation timeout
            page.set_default_timeout(self.options.timeout)
            page.set_default_navigation_timeout(self.options.timeout)

            return page

        except Exception as e:
            logger.error(f"Failed to create new page: {str(e)}")
            raise

    def fetch(self, url: str, headers: Optional[Dict] = None) -> Dict[str, Any]:
        if not self.context: self.init()
        page = self.new_page()
        if headers: page.set_extra_http_headers(headers)
        
        try:
            response = page.goto(url, timeout=self.options.timeout, wait_until="networkidle")
            html = page.content()
            current_url = page.url
            
            headers_dict = response.headers if response else {}
            cookies_list = self.context.cookies(current_url)
            cookies = {c['name']: c['value'] for c in cookies_list}
            
            data = _parse_html_common(html, current_url)
            data.update({
                'status': response.status if response else 0,
                'headers': {k.lower(): v for k, v in headers_dict.items()},
                'cookies': cookies,
            })
            return data
        finally:
            page.close()

    def destroy(self) -> None:
        if self.context: self.context.close()
        if self.browser: self.browser.close()
        if self.playwright_mgr: self.playwright_mgr.stop()

class SyncHttpOnlyDriver:
    """Blocking HTTP driver using requests"""
    def __init__(self):
        self._session = requests.Session()
        self._session.headers.update({"User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/147.0.0.0 Safari/537.36"})

    def __enter__(self):
        self.init()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.destroy()

    def init(self) -> None:
        pass # Requests session is initialized in __init__

    def fetch(self, url: str, headers: Optional[Dict] = None) -> Dict[str, Any]:
        resp = self._session.get(url, headers=headers, timeout=30)
        data = _parse_html_common(resp.text, resp.url)
        data.update({
            'status': resp.status_code,
            'headers': {k.lower(): v for k, v in resp.headers.items()},
            'cookies': resp.cookies.get_dict()
        })
        return data

    def destroy(self) -> None:
        self._session.close()
