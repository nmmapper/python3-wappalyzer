"""Site analyzer - Manages analysis of a single website"""

import asyncio
import logging
from typing import Dict, Optional, Any, List, Callable, Set
from dataclasses import dataclass, field
from urllib.parse import urljoin, urlparse
import dns.resolver
import dns.rdatatype

from wappalyzer_core import Wappalyzer


logging.basicConfig(
    level=logging.INFO,
    format="[%(asctime)s] %(levelname)s %(name)s: %(message)s"
)
logger = logging.getLogger("Site")


@dataclass
class AnalysisOptions:
    """Options for site analysis"""
    max_depth: int = 3
    max_urls: int = 10
    max_wait: int = 5000
    recursive: bool = False
    probe: Optional[str] = None  # None, 'basic', or 'full'
    delay: int = 500
    no_scripts: bool = False
    no_redirect: bool = False
    debug: bool = False
    headers: Dict[str, str] = field(default_factory=dict)


class Site:
    """Analyzes a single website"""

    def __init__(self,
                 url: str,
                 driver,
                 analyzer: Wappalyzer,
                 options: Optional[AnalysisOptions] = None):
        """
        Initialize site analyzer.

        Args:
            url: URL to analyze
            driver: Browser driver instance
            analyzer: Wappalyzer core analyzer
            options: Analysis options
        """
        self.url = url
        self.driver = driver
        self.analyzer = analyzer
        self.options = options or AnalysisOptions()

        try:
            self.parsed_url = urlparse(url)
        except Exception as e:
            raise ValueError(f"Invalid URL: {url}") from e

        # Tracking
        self.analyzed_urls: Set[str] = set()
        self.analyzed_xhr: Dict[str, Set[str]] = {}
        self.detections: List[Dict[str, Any]] = []
        self.pages: List[Any] = []

        # Event handlers
        self._event_handlers: Dict[str, List[Callable]] = {
            'request': [],
            'response': [],
            'goto': [],
            'analyze': [],
            'error': [],
            'log': [],
        }

        self._destroyed = False
        self._xhr_debounce: Set[str] = set()

    async def goto(self, url: str) -> Dict[str, Any]:
        """
        Navigate to a URL and extract page data.

        Args:
            url: URL to navigate to

        Returns:
            Extracted page data
        """
        if self._destroyed:
            return {}

        # Check for duplicates
        if url in self.analyzed_urls:
            return {}

        self.analyzed_urls.add(url)

        self._log(f"Navigate to {url}")

        try:
            page = await self.driver.new_page()
            self.pages.append(page)

            # Set up interception
            await page.route('**/*', self._on_request)

            # Set up response listener
            page.on('response', self._on_response)

            # Navigate to URL
            #response = await page.goto(url, wait_until='networkidle')
            response = await page.goto(url, wait_until='domcontentloaded')

            # Extract page data
            page_data = await self._extract_page_data(page, url, response)

            # Analyze extracted data
            await self.onDetect(url, page_data)

            # Emit goto event
            await self._emit('goto', page_data)

            return page_data

        except Exception as e:
            self._error(f"Failed to navigate to {url}: {str(e)}")
            return {}

        finally:
            try:
                await page.close()
            except Exception:
                pass

    async def analyze(self) -> List[Dict[str, Any]]:
        """
        Analyze the site and return detected technologies.

        Returns:
            List of detected technologies
        """
        try:
            # Start with main page
            await self.goto(self.url)

            # Perform probe if requested
            if self.options.probe:
                await self._probe()
            
            # Resolve and return results (using correct method name)
            results = self.analyzer.resolve(self.detections)
            
            await self._emit('analyze', {
                'urls': list(self.analyzed_urls),
                'technologies': results,
            })

            return results

        except Exception as e:
            raise 
            self._error(f"Analysis failed: {str(e)}")
            return []

    async def _extract_page_data(self,
                                 page,
                                 url: str,
                                 response) -> Dict[str, Any]:
        """
        Extract page data for analysis.

        Args:
            page: Playwright page
            url: Current URL
            response: Page response

        Returns:
            Extracted page data
        """
        try:
            data = {
                'url': url,
                'html': await page.content(),
                'text': await page.evaluate('() => document.body.innerText'),
                'scriptSrc': await self._extract_script_src(page),
                'scripts': await self._extract_scripts(page),
                'meta': await self._extract_meta(page),
                'cookies': await self._extract_cookies(page),
                'headers': {},
            }

            # Extract response headers
            if response:
                headers = {}
                for key, value in response.headers.items():
                    headers[key] = [value]
                data['headers'] = headers

            # Execute JavaScript analysis
            if not self.options.no_scripts:
                data['js'] = await self._analyze_javascript(page)

            return data

        except Exception as e:
            self._error(f"Failed to extract page data: {str(e)}")
            return {}

    async def _extract_script_src(self, page) -> List[str]:
        """Extract script source URLs"""
        try:
            return await page.evaluate('''
                () => Array.from(document.scripts)
                    .map(s => s.src)
                    .filter(s => s)
            ''')
        except Exception:
            return []

    async def _extract_scripts(self, page) -> List[str]:
        """Extract inline script content"""
        try:
            return await page.evaluate('''
                () => Array.from(document.scripts)
                    .map(s => s.textContent)
                    .filter(s => s && s.trim())
            ''')
        except Exception:
            return []

    async def _extract_meta(self, page) -> Dict[str, List[str]]:
        """Extract meta tags"""
        try:
            return await page.evaluate('''
                () => {
                    const meta = {};
                    document.querySelectorAll('meta').forEach(m => {
                        const name = m.getAttribute('name') || 
                                   m.getAttribute('property');
                        const content = m.getAttribute('content');
                        if (name && content) {
                            meta[name] = [content];
                        }
                    });
                    return meta;
                }
            ''')
        except Exception:
            return {}

    async def _extract_cookies(self, page) -> Dict[str, str]:
        """Extract cookies"""
        try:
            cookies = await page.context.cookies()
            return {c['name']: c['value'] for c in cookies}
        except Exception:
            return {}

    async def _analyze_javascript(self, page) -> List[Dict[str, Any]]:
        """
        Analyze JavaScript objects and properties.

        Returns:
            List of detected JavaScript properties
        """
        try:
            # Get list of JS patterns to look for
            js_patterns = [
                tech for tech in self.analyzer.technologies.values()
                if 'js' in tech
            ]

            detections = []

            for tech in js_patterns:
                tech_name = tech['name']
                js_chains = tech.get('js', {})

                for chain_name in js_chains:
                    try:
                        # Convert bracket notation to dot notation
                        chain = chain_name.replace('[', '.').replace(']', '')
                        value = await page.evaluate(f'''
                            () => {{
                                try {{
                                    return {chain};
                                }} catch (e) {{
                                    return undefined;
                                }}
                            }}
                        ''')

                        if value is not None and value != 'undefined':
                            detections.append({
                                'technology': tech,
                                'chain': chain_name,
                                'value': str(value),
                            })
                    except Exception:
                        pass

            return detections

        except Exception as e:
            self._error(f"JavaScript analysis failed: {str(e)}")
            return []

    async def _probe(self) -> None:
        """
        Perform deeper analysis (robots.txt, DNS, etc.).
        """
        try:
            if self.options.probe == 'basic' or self.options.probe == 'full':
                # Fetch robots.txt
                await self._probe_robots()

            if self.options.probe == 'full':
                # Perform DNS lookups
                await self._probe_dns()

        except Exception as e:
            self._error(f"Probe failed: {str(e)}")

    async def _probe_robots(self) -> None:
        """Fetch and analyze robots.txt"""
        try:
            import aiohttp

            robots_url = urljoin(self.url, '/robots.txt')

            async with aiohttp.ClientSession() as session:
                async with session.get(robots_url, timeout=aiohttp.ClientTimeout(total=10)) as resp:
                    if resp.status == 200:
                        robots_content = await resp.text()
                        await self.onDetect(robots_url, {'robots': robots_content})

        except Exception as e:
            print("Probe has totally failed")
            self._error(f"robots.txt probe failed: {str(e)}")

    async def _probe_dns(self) -> None:
        """Perform DNS lookups"""
        try:
            hostname = self.parsed_url.netloc

            dns_records = {}

            # Query common record types
            for record_type in ['A', 'MX', 'TXT', 'NS']:
                try:
                    answers = dns.resolver.resolve(hostname, record_type)
                    dns_records[record_type.lower()] = [
                        str(rr) for rr in answers
                    ]
                except Exception:
                    pass

            await self.onDetect(self.url, {'dns': dns_records})

        except Exception as e:
            self._error(f"DNS probe failed: {str(e)}")

    async def onDetect(self, url: str, page_data: Dict[str, Any]) -> None:
        """
        Analyze extracted page data and store detections.

        Args:
            url: URL analyzed
            page_data: Extracted page data
        """
        try:
            results = self.analyzer.analyze(page_data)
            self.detections.extend(results)
        except Exception as e:
            self._error(f"Detection failed: {str(e)}")

    async def _on_request(self, route, request) -> None:
        """Handle page requests (for interception/logging)"""
        try:
            await self._emit('request', {
                'url': request.url,
                'method': request.method,
                'headers': request.headers,
            })

            # Continue with request
            await route.continue_()

        except Exception as e:
            self._error(f"Request handler failed: {str(e)}")

    async def _on_response(self, response) -> None:
        """Handle page responses"""
        try:
            await self._emit('response', {
                'url': response.url,
                'status': response.status,
                'headers': dict(response.headers),
            })
        except Exception as e:
            self._error(f"Response handler failed: {str(e)}")

    async def cleanup(self) -> None:
        """Clean up resources"""
        self._destroyed = True

        for page in self.pages:
            try:
                await page.close()
            except Exception:
                pass

    def on(self, event: str, callback: Callable) -> None:
        """Register event listener"""
        if event not in self._event_handlers:
            self._event_handlers[event] = []

        self._event_handlers[event].append(callback)

    async def _emit(self, event: str, data: Any) -> None:
        """Emit event"""
        if event not in self._event_handlers:
            return

        for callback in self._event_handlers[event]:
            try:
                if asyncio.iscoroutinefunction(callback):
                    await callback(data)
                else:
                    callback(data)
            except Exception as e:
                logger.error(f"Event handler error: {str(e)}")

    def _log(self, message: str) -> None:
        """Log message"""
        if self.options.debug:
            logger.info(message)

    def _error(self, message: str) -> None:
        """Log error"""
        logger.error(message)

class SiteSync(Site):
    """
    Synchronous site analyzer.
    Inherits state from Site but overrides async methods with sync versions.
    """
    
    def goto(self, url: str) -> Dict[str, Any]:
        if self._destroyed:
            return {}

        # Check for duplicates
        if url in self.analyzed_urls:
            return {}

        self.analyzed_urls.add(url)

        self._log(f"Navigate to {url}")

        try:
            page = self.driver.new_page()
            self.pages.append(page)

            # Set up interception
            page.route('**/*', self._on_request)

            # Set up response listener
            page.on('response', self._on_response)

            # Navigate to URL
            response = page.goto(url, wait_until='networkidle')

            # Extract page data
            page_data = self._extract_page_data(page, url, response)

            # Analyze extracted data
            self.onDetect(url, page_data)

            # Emit goto event
            self._emit('goto', page_data)

            return page_data

        except Exception as e:
            self._error(f"Failed to navigate to {url}: {str(e)}")
            return {}

        finally:
            try:
                page.close()
            except Exception:
                pass

    def analyze(self) -> List[Dict[str, Any]]:
        """
        Analyze the site and return detected technologies.

        Returns:
            List of detected technologies
        """
        try:
            # Start with main page
            self.goto(self.url)

            # Perform probe if requested
            if self.options.probe:
                self._probe()
            
            # Resolve and return results (using correct method name)
            results = self.analyzer.resolve(self.detections)
            
            self._emit('analyze', {
                'urls': list(self.analyzed_urls),
                'technologies': results,
            })

            return results

        except Exception as e:
            raise 
            self._error(f"Analysis failed: {str(e)}")
            return []

    def _extract_page_data(self,
                                 page,
                                 url: str,
                                 response) -> Dict[str, Any]:
        try:
            data = {
                'url': url,
                'html': page.content(),
                'text': page.evaluate('() => document.body.innerText'),
                'scriptSrc': self._extract_script_src(page),
                'scripts': self._extract_scripts(page),
                'meta': self._extract_meta(page),
                'cookies': self._extract_cookies(page),
                'headers': {},
            }

            # Extract response headers
            if response:
                headers = {}
                for key, value in response.headers.items():
                    headers[key] = [value]
                data['headers'] = headers

            # Execute JavaScript analysis
            if not self.options.no_scripts:
                data['js'] = self._analyze_javascript(page)

            return data

        except Exception as e:
            self._error(f"Failed to extract page data: {str(e)}")
            return {}

    def _extract_script_src(self, page) -> List[str]:
        """Extract script source URLs"""
        try:
            return page.evaluate('''
                () => Array.from(document.scripts)
                    .map(s => s.src)
                    .filter(s => s)
            ''')
        except Exception:
            return []

    def _extract_scripts(self, page) -> List[str]:
        """Extract inline script content"""
        try:
            return page.evaluate('''
                () => Array.from(document.scripts)
                    .map(s => s.textContent)
                    .filter(s => s && s.trim())
            ''')
        except Exception:
            return []

    def _extract_meta(self, page) -> Dict[str, List[str]]:
        """Extract meta tags"""
        try:
            return page.evaluate('''
                () => {
                    const meta = {};
                    document.querySelectorAll('meta').forEach(m => {
                        const name = m.getAttribute('name') || 
                                   m.getAttribute('property');
                        const content = m.getAttribute('content');
                        if (name && content) {
                            meta[name] = [content];
                        }
                    });
                    return meta;
                }
            ''')
        except Exception:
            return {}

    def _extract_cookies(self, page) -> Dict[str, str]:
        """Extract cookies"""
        try:
            cookies = page.context.cookies()
            return {c['name']: c['value'] for c in cookies}
        except Exception:
            return {}

    def _analyze_javascript(self, page) -> List[Dict[str, Any]]:
        """
        Analyze JavaScript objects and properties.

        Returns:
            List of detected JavaScript properties
        """
        try:
            # Get list of JS patterns to look for
            js_patterns = [
                tech for tech in self.analyzer.technologies.values()
                if 'js' in tech
            ]

            detections = []

            for tech in js_patterns:
                tech_name = tech['name']
                js_chains = tech.get('js', {})

                for chain_name in js_chains:
                    try:
                        # Convert bracket notation to dot notation
                        chain = chain_name.replace('[', '.').replace(']', '')
                        value = page.evaluate(f'''
                            () => {{
                                try {{
                                    return {chain};
                                }} catch (e) {{
                                    return undefined;
                                }}
                            }}
                        ''')

                        if value is not None and value != 'undefined':
                            detections.append({
                                'technology': tech,
                                'chain': chain_name,
                                'value': str(value),
                            })
                    except Exception:
                        pass

            return detections

        except Exception as e:
            self._error(f"JavaScript analysis failed: {str(e)}")
            return []

    def _probe(self) -> None:
        """
        Perform deeper analysis (robots.txt, DNS, etc.).
        """
        try:
            #:: todo
            pass 
        except Exception as e:
            self._error(f"Probe failed: {str(e)}")
    
    def onDetect(self, url: str, page_data: Dict[str, Any]) -> None:
        """
        Analyze extracted page data and store detections.

        Args:
            url: URL analyzed
            page_data: Extracted page data
        """
        try:
            results = self.analyzer.analyze(page_data)
            self.detections.extend(results)
        except Exception as e:
            self._error(f"Detection failed: {str(e)}")
            
    def _on_request(self, route, request) -> None:
        """Handle page requests (for interception/logging)"""
        try:
            self._emit('request', {
                'url': request.url,
                'method': request.method,
                'headers': request.headers,
            })

            # Continue with request
            route.continue_()

        except Exception as e:
            self._error(f"Request handler failed: {str(e)}")

    def _on_response(self, response) -> None:
        """Handle page responses"""
        try:
            self._emit('response', {
                'url': response.url,
                'status': response.status,
                'headers': dict(response.headers),
            })
        except Exception as e:
            self._error(f"Response handler failed: {str(e)}")

    def cleanup(self) -> None:
        """Clean up resources"""
        self._destroyed = True

        for page in self.pages:
            try:
                page.close()
            except Exception:
                pass

    def on(self, event: str, callback: Callable) -> None:
        """Register event listener"""
        if event not in self._event_handlers:
            self._event_handlers[event] = []

        self._event_handlers[event].append(callback)

    def _emit(self, event: str, data: Any) -> None:
        """Emit event"""
        if event not in self._event_handlers:
            return

        for callback in self._event_handlers[event]:
            try:
                if asyncio.iscoroutinefunction(callback):
                    callback(data)
                else:
                    callback(data)
            except Exception as e:
                logger.error(f"Event handler error: {str(e)}")
