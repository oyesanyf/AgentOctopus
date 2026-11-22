"""Module entrypoint for `python -m tests.e2e_release`."""

from .run_e2e import main

if __name__ == "__main__":
    raise SystemExit(main())
