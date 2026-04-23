"""Wappalyzer core - Technology detection engine"""

from wappalyzer_core.analyzer import Wappalyzer
from wappalyzer_core.patterns import PatternParser, Pattern, PatternCompiler
from wappalyzer_core.browser import AsyncPlaywrightDriver, BrowserOptions, SyncPlaywrightDriver, AsyncHttpOnlyDriver,SyncHttpOnlyDriver
from wappalyzer_core.wappalyzer_driver import WappalyzerDriver,SyncWappalyzerDriver
from wappalyzer_core.site import Site

__version__ = "6.10.62"
__all__ = ["Wappalyzer", "PatternParser", "Pattern", "PatternCompiler", 'SyncPlaywrightDriver', 'AsyncPlaywrightDriver', 'Site', 'WappalyzerDriver', 'BrowserOptions',
            'SyncWappalyzerDriver','AsyncHttpOnlyDriver']
