import os
import time

from central.core.plugins import PluginSettings
from central.plugins import load_plugins, registry


def run() -> None:
    settings = PluginSettings()
    load_plugins(settings.modules)
    scanner_name = os.getenv("SCANNER_PLUGIN", settings.default_scanner)
    scanner = registry.create(scanner_name, {"source": "collector"})
    result = scanner.run({"targets": ["10.0.0.0/24"]})
    print(f"scan result: {result}")
    while True:
        print("collector heartbeat")
        time.sleep(5)


if __name__ == "__main__":
    run()
