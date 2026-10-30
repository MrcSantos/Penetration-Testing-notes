#!/usr/bin/env python3

import argparse
import sys
from pathlib import Path

#---------- Initialized later env variables ----------#

LOG_FILENAME = ""

#---------- Initialized later env variables ----------#

#---------- Logger ----------#

def write_to_log_file(message: str) -> None:
    with open(LOG_FILENAME, "a") as f:
        f.write(f"{message}\n")

def init_log_file() -> None:
    """Create a new log file and write the initial message."""
    write_to_log_file("Hello world!")

#---------- Logger ----------#

#---------- Main ----------#

def main(args: argparse.Namespace) -> int:
    try:
        global LOG_FILENAME
        LOG_FILENAME = args.log
        init_log_file()
        print(f"Log file created successfully: {LOG_FILENAME}")
    except (ValueError, OSError) as error:
        print(f"Error: {error}", file=sys.stderr)
        return 1

    return 0

#---------- Main ----------#

#---------- Main call and argparse init ----------#

def parse_arguments() -> argparse.Namespace:
    """Parse command-line arguments."""
    parser = argparse.ArgumentParser(
        description="Initialize the Nmap wrapper."
    )
    parser.add_argument(
        "-l",
        "--log",
        type=Path,
        default=Path("./fscanner.log"),
        help="Path to the log file (default: ./fscanner.log).",
    )

    return parser.parse_args()


if __name__ == "__main__":
    args = parse_arguments()
    sys.exit(main(args))

#---------- Main call and argparse init ----------#
