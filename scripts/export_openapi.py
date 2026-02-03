from __future__ import annotations

import json
from pathlib import Path

from central.api.app import app


def main() -> None:
    output_path = Path("docs/api/central-openapi.json")
    output_path.parent.mkdir(parents=True, exist_ok=True)
    spec = app.openapi()
    output_path.write_text(
        json.dumps(spec, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    print(f"Wrote {output_path}")


if __name__ == "__main__":
    main()
