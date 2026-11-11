"""Run the bootstrap from a fresh checkout without installing: ``python scripts/bootstrap.py --workspace DIR``."""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from rea_mcp.bootstrap import main  # noqa: E402

if __name__ == "__main__":
    raise SystemExit(main())
