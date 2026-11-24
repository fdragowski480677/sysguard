"""Entry point: `python -m sysguard` (CLI) or `python -m sysguard --gui`."""

from __future__ import annotations

import sys


def main() -> int:
    if "--gui" in sys.argv:
        sys.argv.remove("--gui")
        from .gui import main as gui_main
        return gui_main()
    from .cli import main as cli_main
    return cli_main()


if __name__ == "__main__":
    raise SystemExit(main())
