def get_defaults_for_port(port):
    """
    Returns default credential pairs for known audit ports.
    """
    defaults = {
        21: [("anonymous", "anonymous@"), ("root", "root"), ("admin", "admin"), ("ftp", "ftp")],
        22: [("root", "root"), ("admin", "password"), ("ubuntu", "ubuntu"), ("admin", "admin")],
        80: [("admin", "admin"), ("admin", "password"), ("root", "root"), ("tomcat", "tomcat"), ("admin", "")],
        443: [("admin", "admin"), ("admin", "password"), ("root", "root")],
        3306: [("root", ""), ("root", "root"), ("admin", "admin"), ("mysql", "mysql")],
        5432: [("postgres", "postgres"), ("postgres", "password"), ("admin", "admin")],
        8080: [("admin", "admin"), ("admin", "password"), ("root", "root"), ("tomcat", "tomcat"), ("admin", "")]
    }
    return defaults.get(port, [("admin", "admin"), ("root", "root")])
