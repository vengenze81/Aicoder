import re

SECRET_PATTERNS = {
    "AWS Access Key ID": re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
    "AWS Secret Access Key": re.compile(r"(?i)aws[_-]?secret[_-]?access[_-]?key['\"\s]*[:=]['\"\s]*([A-Za-z0-9/+=]{40})"),
    "GitHub Personal Access Token": re.compile(r"\bghp_[a-zA-Z0-9]{36}\b"),
    "Private Key": re.compile(r"-----BEGIN (?:RSA|EC|DSA|OPENSSH) PRIVATE KEY-----"),
    "Slack Token": re.compile(r"\bxox[baprs]-[0-9a-zA-Z]{10,48}\b"),
    "Stripe Live API Key": re.compile(r"\bsk_live_[0-9a-zA-Z]{24}\b"),
    "Google API Key": re.compile(r"\bAIza[0-9A-Za-z-_]{35}\b"),
    "Database URI Connection String": re.compile(r"\b(?:postgres|mysql|mongodb|redis|sqlite):\/\/[^\s]+", re.IGNORECASE),
    "Email Address": re.compile(r"\b[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}\b"),
    "Generic API Key / Auth Token": re.compile(r"(?i)(?:api[_-]?key|secret[_-]?key|auth[_-]?token|bearer)['\"\s]*[:=]['\"\s]*([a-zA-Z0-9_\-\.]{16,64})")
}

def extract_secrets(text):
    """Scans text for sensitive tokens and patterns using regex."""
    found_secrets = []
    if not text:
        return found_secrets
        
    for name, pattern in SECRET_PATTERNS.items():
        matches = pattern.findall(text)
        if matches:
            cleaned_matches = []
            for m in matches:
                if isinstance(m, tuple):
                    cleaned_matches.extend([sub for sub in m if sub])
                else:
                    cleaned_matches.append(m)
            if cleaned_matches:
                found_secrets.append({
                    "secret_type": name,
                    "matches": list(set(cleaned_matches))
                })
    return found_secrets
