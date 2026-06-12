"""
PhishGuard — Configuration Module
Loads environment variables and exposes application settings.
"""

import os
from dotenv import load_dotenv

# Load .env file if present
load_dotenv()

# ── API Keys ─────────────────────────────────────────────────────────────────

VIRUSTOTAL_API_KEY = os.environ.get('VIRUSTOTAL_API_KEY', '').strip()
BUILTWITH_API_KEY = os.environ.get('BUILTWITH_API_KEY', '').strip()
SECRET_KEY = os.environ.get('SECRET_KEY', 'phishguard-dev-key')

# ── Feature Flags (auto-detect based on available keys) ──────────────────────

VIRUSTOTAL_ENABLED = bool(VIRUSTOTAL_API_KEY and VIRUSTOTAL_API_KEY != 'your_virustotal_api_key_here')
BUILTWITH_ENABLED = bool(BUILTWITH_API_KEY)

# ── Request Settings ─────────────────────────────────────────────────────────

REQUEST_TIMEOUT = int(os.environ.get('REQUEST_TIMEOUT', '5'))
MAX_REDIRECTS = 5

# ── Cache Settings ───────────────────────────────────────────────────────────

SCAN_CACHE_MAX_SIZE = 100  # Max number of scan results to keep in memory
SCAN_CACHE_TTL = 3600      # Cache TTL in seconds (1 hour)
