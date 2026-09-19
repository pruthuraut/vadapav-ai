"""bb-harness entrypoint: python -m bb_harness"""
import sys
from bb_harness.cli.repl import main

if __name__ == "__main__":
    sys.exit(main())
