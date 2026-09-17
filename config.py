# Framework Configuration & Global Settings

PROXY_LIST = [
    "http://141.98.153.86:80",
    "http://130.110.103.245:3128",
    "http://178.18.244.8:8888",
    "http://159.65.245.255:80"
]

USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) SecurityAuditor/1.0",
    "Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/115.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/16.5 Safari/605.1.15"
]

WAF_SIGNATURES = [
    "cloudflare",
    "wordfence",
    "sucuri",
    "incapsula",
    "akamaighost"
]

DEFAULT_HEADERS = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) SecurityAuditor/1.0",
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
    "Accept-Language": "en-US,en;q=0.5"
}
