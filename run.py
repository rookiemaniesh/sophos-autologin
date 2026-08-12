"""PyInstaller entry point. Keeping this separate from the package keeps
the frozen exe's sys.argv[0] handling simple."""

import sys

from sophos_autologin.__main__ import main

if __name__ == "__main__":
    sys.exit(main())
