"""
Configuration for Panopticon CVE Map.
Loads environment variables and defines application constants.
"""
import os
from dotenv import load_dotenv

load_dotenv()

# NVD API Configuration
NVD_API_KEY = os.getenv("NVD_API_KEY")
NVD_BASE_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"

# Rate limiting (requests per 30s window)
NVD_RATE_LIMIT = 50 if NVD_API_KEY else 5
NVD_RATE_WINDOW = 30
NVD_REQUEST_DELAY = NVD_RATE_WINDOW / NVD_RATE_LIMIT

# Graph rendering limits
MAX_GRAPH_NODES = 100  # Reduced from 300 for readability
MAX_EGO_DEPTH = 2

# Filter by publication year (only CVEs after this year)
MIN_PUBLISH_YEAR = 2020

# Database
DB_PATH = "panopticon.db"

# Debug helper (NOT for production):
# from utils import mask_api_key
# logger.debug(f"NVD API Key: {mask_api_key(NVD_API_KEY)}")