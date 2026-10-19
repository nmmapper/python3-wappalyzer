"""Browser automation layer using Playwright - Fixed and Enhanced"""

import asyncio
import logging
import re
import socket
import ipaddress
from urllib.parse import urlparse
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

def is_safe_url(url: str) -> bool:
    """SSRF prevention: Ensure target does not resolve to local or private IPs"""
    try:
        hostname = urlparse(url).hostname
        if not hostname: 
            return False
            
        # getaddrinfo handles both IPv4 and IPv6 robustly across different OS environments
        addr_info = socket.getaddrinfo(hostname, None)
        
        for result in addr_info:
            ip = result[4][0]
            
            # Strip IPv6 scope IDs (e.g., %eth0) which crash the ipaddress module
            if '%' in ip:
                ip = ip.split('%')[0]
                
            parsed_ip = ipaddress.ip_address(ip)
            
            if parsed_ip.is_private or parsed_ip.is_loopback or parsed_ip.is_link_local or parsed_ip.is_multicast:
                logger.warning(f"SSRF Blocked: {url} resolves to internal IP {ip}")
                return False
                
        return True
    except Exception as e:
        # Log the exact exception so DNS failures aren't hidden
        logger.error(f"SSRF DNS resolution failed for {url}: {str(e)}")
        return False

def _parse_html_common(html: str, url: str) -> Dict[str, Any]:
    # LXML is substantially faster for large DOMs than html.parser
    soup = BeautifulSoup(html, 'lxml')
    
    meta = {}
    for t in soup.find_all('meta'):
        name = t.get('name') or t.get('property')
        content = t.get('content')
        if name and content:
            if name not in meta: meta[name] = []
            meta[name].append(content)
            
    script_src = [t.get('src') for t in soup.find_all('script') if t.get('src')]
    scripts = [t.string for t in soup.find_all('script') if t.string]
    
    return {
        'url': url,
        'html': html,
        'meta': meta,
        'scriptSrc': script_src,
        'scripts': scripts,
        'text': soup.get_text(separator=' ', strip=True)
    }

class AsyncPlaywrightDriver:
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
        if not self.context:
            raise RuntimeError("Browser context not initialized. Call init() first.")
        try:
            page = await self.context.new_page()
            page.set_default_timeout(self.options.timeout)
            page.set_default_navigation_timeout(self.options.timeout)
            return page
        except Exception as e:
            logger.error(f"Failed to create new page: {str(e)}")
            raise

    async def fetch(self, url: str, headers: Optional[Dict] = None) -> Dict[str, Any]:
        if not is_safe_url(url):
            raise ValueError("Unsafe URL targeted.")
            
        if not self.context: await self.init()
        page = await self.new_page()
        if headers: await page.set_extra_http_headers(headers)
        
        try:
            response = await page.goto(url, timeout=self.options.timeout, wait_until="networkidle")
            html = await page.content()
            current_url = page.url
            status = response.status if response else 0
            
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
    def __init__(self, options: Optional[BrowserOptions] = None):
        self.options = options or BrowserOptions()
        self._session: Optional[aiohttp.ClientSession] = None

    async def __aenter__(self):
        await self.init()
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        await self.destroy()

    async def init(self) -> None:
        if not self._session:
            self._session = aiohttp.ClientSession(headers={"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/154.0.0.0 Safari/537.36"})

    async def fetch(self, url: str, headers: Optional[Dict] = None) -> Dict[str, Any]:
        if not is_safe_url(url):
            raise ValueError("Unsafe URL targeted.")
            
        if not self._session: await self.init()
        req_timeout = self.options.timeout / 1000.0  # convert ms to seconds
        
        async with self._session.get(url, headers=headers, timeout=aiohttp.ClientTimeout(total=req_timeout)) as resp:
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

class SyncPlaywrightDriver:
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
        if not self.context:
            raise RuntimeError("Browser context not initialized. Call init() first.")
        try:
            page = self.context.new_page()
            page.set_default_timeout(self.options.timeout)
            page.set_default_navigation_timeout(self.options.timeout)
            return page
        except Exception as e:
            logger.error(f"Failed to create new page: {str(e)}")
            raise

    def fetch(self, url: str, headers: Optional[Dict] = None) -> Dict[str, Any]:
        if not is_safe_url(url):
            raise ValueError("Unsafe URL targeted.")
            
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
    def __init__(self, options: Optional[BrowserOptions] = None):
        self.options = options or BrowserOptions()
        self._session = requests.Session()
        self._session.headers.update({"User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/147.0.0.0 Safari/537.36"})

    def __enter__(self):
        self.init()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.destroy()

    def init(self) -> None:
        pass 

    def fetch(self, url: str, headers: Optional[Dict] = None) -> Dict[str, Any]:
        if not is_safe_url(url):
            raise ValueError("Unsafe URL targeted.")
            
        req_timeout = self.options.timeout / 1000.0  # convert ms to seconds
        resp = self._session.get(url, headers=headers, timeout=req_timeout)
        data = _parse_html_common(resp.text, resp.url)
        data.update({
            'status': resp.status_code,
            'headers': {k.lower(): v for k, v in resp.headers.items()},
            'cookies': resp.cookies.get_dict()
        })
        return data

    def destroy(self) -> None:
        self._session.close()
