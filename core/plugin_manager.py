import os
import importlib

class PluginManager:
    def __init__(self, plugin_dir="plugins"):
        self.plugin_dir = plugin_dir
        self.plugins = {}

    def discover_plugins(self):
        if not os.path.exists(self.plugin_dir):
            os.makedirs(self.plugin_dir)
            
        for filename in os.listdir(self.plugin_dir):
            if filename.endswith(".py") and not filename.startswith("__"):
                module_name = filename[:-3]
                try:
                    module = importlib.import_module(f"{self.plugin_dir}.{module_name}")
                    if hasattr(module, "PLUGIN_META") and hasattr(module, "run"):
                        self.plugins[module_name] = {
                            "meta": module.PLUGIN_META,
                            "run": module.run
                        }
                    else:
                        print(f"[-] Plugin {module_name} missing PLUGIN_META or run()")
                except Exception as e:
                    print(f"[-] Failed to load plugin {module_name}: {e}")
        return self.plugins
