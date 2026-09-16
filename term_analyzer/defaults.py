SERVICE_DEFAULT_CREDENTIALS = {
    8080: [
        ("admin", "admin"),
        ("admin", "password"),
        ("root", "root"),
        ("tomcat", "tomcat"),
        ("admin", ""),
    ],
    80: [
        ("admin", "admin"),
        ("admin", "password"),
        ("root", "toor"),
        ("administrator", "password"),
    ],
    443: [
        ("admin", "admin"),
        ("admin", "password"),
    ],
    3306: [
        ("root", ""),
        ("root", "root"),
        ("admin", "admin"),
    ],
    5432: [
        ("postgres", "postgres"),
        ("postgres", ""),
    ],
    22: [
        ("root", "root"),
        ("root", "toor"),
        ("admin", "admin"),
    ],
    21: [
        ("anonymous", "anonymous"),
        ("root", "root"),
        ("admin", "admin"),
    ],
    23: [
        ("admin", "admin"),
        ("root", "root"),
        ("admin", "password"),
    ],
}

def get_defaults_for_port(port: int):
    """Retrieve default credential pairs for a given port."""
    return SERVICE_DEFAULT_CREDENTIALS.get(port, [("admin", "admin"), ("admin", "password")])
