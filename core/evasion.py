import random
import asyncio

USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2.1 Safari/605.1.15",
    "Mozilla/5.0 (X11; Linux x86_64; rv:123.0) Gecko/20100101 Firefox/123.0",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:123.0) Gecko/20100101 Firefox/123.0",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_4 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Mobile/15E148 Safari/604.1"
]

SPOOF_IPS = [
    "127.0.0.1",
    "192.168.1.100",
    "10.0.0.50",
    "172.16.0.25"
]

def get_evasion_headers():
    """Generates randomized headers to evade static fingerprinting."""
    headers = {
        "User-Agent": random.choice(USER_AGENTS),
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
        "Accept-Language": "en-US,en;q=0.5",
        "X-Forwarded-For": random.choice(SPOOF_IPS),
        "X-Originating-IP": random.choice(SPOOF_IPS),
        "Cache-Control": "no-cache"
    }
    return headers

async def apply_jitter(min_sec=0.2, max_sec=1.0):
    """Introduces random sleep intervals to prevent rate-limit detection."""
    delay = random.uniform(min_sec, max_sec)
    await asyncio.sleep(delay)
