"""Allow ``python -m iac_change_control`` as an alias for ``python -m iac_change_control.cli``."""

from iac_change_control.cli import main

raise SystemExit(main())
