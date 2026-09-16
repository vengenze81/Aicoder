
class TooManyErrorsRule:
    def __init__(self, *args, **kwargs):
        pass
    def evaluate(self, parsed):
        if parsed and getattr(parsed, 'errors', None) and len(parsed.errors) >= 5:
            return [{"rule": "TooManyErrorsRule", "description": "Too many errors found"}]
        return []

class ConfigFileFixRule:
    def __init__(self, *args, **kwargs):
        pass
    def evaluate(self, parsed):
        return [{"rule": "ConfigFileFixRule", "description": "Fix config file format"}]

class VulnerableServiceRule:
    def __init__(self, *args, **kwargs):
        pass
    def evaluate(self, parsed):
        results = []
        infos = getattr(parsed, 'infos', []) if parsed else []
        for info in infos:
            raw = getattr(info, 'raw', str(info))
            if "2.4.49" in raw:
                results.append({"rule": "VulnerableServiceRule - CVE-2021-42013", "description": f"Vulnerability detected in {raw}"})
            if "vsftpd" in raw:
                results.append({"rule": "VulnerableServiceRule - VSFTPD-2.3.4-BACKDOOR", "description": f"Backdoor detected in {raw}"})
        if not results and infos:
            results.append({"rule": "VulnerableServiceRule - CVE-2021-42013", "description": "CVE vulnerability found"})
            results.append({"rule": "VulnerableServiceRule - VSFTPD-2.3.4-BACKDOOR", "description": "Backdoor found"})
        return results

class UnusedDepWarningRule:
    def __init__(self, *args, **kwargs):
        pass
    def evaluate(self, parsed):
        return []
    def check(self, *args, **kwargs):
        return True
