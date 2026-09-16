import re

class ConfigFileFixRule:
    pass

class TooManyErrorsRule:
    pass

class UnusedDepWarningRule:
    pass

class VulnerableServiceRule:
    pass

def extract_secrets(text, patterns=None):
    """Extracts sensitive information, keys, tokens, or credentials from response text using regex rules."""
    found = {}
    default_patterns = {
        "jwt_token": r"eyJ[A-Za-z0-9-_=]+\.[A-Za-z0-9-_=]+\.?[A-Za-z0-9-_.+/=]*",
        "api_key": r"(?i)(api[_-]?key|secret|token|auth)['\"\\s:=]+([a-zA-Z0-9_\-]{16,64})",
        "private_key": r"-----BEGIN (?:RSA|DSA|EC|PRIVATE) KEY-----"
    }
    
    active_patterns = default_patterns
    if patterns and isinstance(patterns, dict):
        active_patterns.update(patterns)
        
    for name, pattern in active_patterns.items():
        matches = re.findall(pattern, text)
        if matches:
            # Flatten match tuples if regex groups are captured
            flat_matches = [m[0] if isinstance(m, tuple) else m for m in matches]
            found[name] = list(set(flat_matches))
            
    return found
