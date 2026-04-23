# python3‑wappalyzer

A clean, up‑to‑date Python wrapper for Wappalyzer – a tool that identifies the technologies used on a website (CMS, frameworks, analytics, etc.).  
The library provides both **synchronous** and **asynchronous** APIs, supports **HTTP‑only** (fast) and **full browser‑based** (accurate) analysis, and is fully compatible with Python ≥ 3.7.

## Features

- 🔍 Detects hundreds of technologies using Wappalyzer’s fingerprints
- 🚀 **HTTP‑only mode** for quick, JavaScript‑free scanning
- 🌐 **Full browser automation** with Playwright for maximum accuracy
- ⚡ **Async & sync** drivers for high‑performance batch analysis
- 📦 Ships with the latest `technologies.json` and `categories.json`
- 🧩 Easily extensible – subclass or replace any component

## Installation

```bash
pip install wappalyzer-core
