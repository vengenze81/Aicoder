PATTERNS = {
    "API Key / Token": r"(?i)(api[_-]?key|access[_-]?token|bearer|auth[_-]?token)[\s'\"]*[:=][\s'\"]*([a-zA-Z0-9_\-\.]{16,64})",
    "Database Error": r"(?i)(sql syntax.*MySQL|unclosed quotation mark|pg_query|syntax error in SQL|sqlite3\.OperationalError)",
    "Private Key": r"-----BEGIN (?:RSA|PRIVATE) KEY-----",
    "Email Address": r"[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+",
    "WordPress Version": r"wp-includes/js/wp-embed\.min\.js\?ver=([0-9\.]+)"
}
