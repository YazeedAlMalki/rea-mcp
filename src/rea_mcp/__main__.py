"""``python -m rea_mcp`` and the ``rea-mcp`` console script."""

from rea_mcp.server import main

__all__ = ["main"]

if __name__ == "__main__":
    raise SystemExit(main())
