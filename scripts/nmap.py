#!/usr/bin/env python3

import argparse
import concurrent.futures
import datetime
import os
import shlex
import shutil
import subprocess
import sys
import threading

from pathlib import Path

#---------- Initialized later env variables ----------#

LOG_FILENAME = Path("./harmony.log")
LOG_LOCK = threading.Lock()
NMAP_LOCATION = ""

#---------- Initialized later env variables ----------#


#---------- Logger ----------#

def write_to_log_file(message: str, write_timestamp: bool = True) -> None:
    """Write a line to the log file."""

    if write_timestamp:
        now_str = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        message = f"[{now_str}] {message}"

    with LOG_LOCK:
        with LOG_FILENAME.open("a", encoding="utf-8") as log_file:
            log_file.write(f"{message}\n")

    print(message)


def end_log_file() -> None:
    """Write the shutdown message."""

    write_to_log_file("Shutting down scanner")


def init_log_file() -> None:
    """Write initial log entries."""

    write_to_log_file("", write_timestamp=False)
    write_to_log_file("", write_timestamp=False)
    write_to_log_file("-- Harmony scanner --", write_timestamp=False)
    write_to_log_file("Starting scanner")


#---------- Logger ----------#


#---------- Environment checks ----------#

def check_root_privileges() -> None:
    """Ensure the scanner is running with root privileges."""

    if os.geteuid() != 0:
        raise PermissionError(
            "This scanner must be executed with root privileges. "
            "Run it using sudo."
        )


def check_nmap_availability() -> str:
    """Check whether Nmap is installed and executable."""

    nmap_path = shutil.which("nmap")

    if nmap_path is None:
        raise FileNotFoundError(
            "Nmap was not found. Please install Nmap before proceeding."
        )

    write_to_log_file(f"Nmap executable found: {nmap_path}")

    return nmap_path


#---------- Environment checks ----------#


#---------- Target handling ----------#

def resolve_targets(targets: list[str]) -> list[str]:
    """Resolve targets as individual arguments or an Nmap input file."""

    if len(targets) != 1:
        return targets

    target_path = Path(targets[0])

    if not target_path.exists():
        return targets

    if not target_path.is_file():
        raise ValueError(
            f"Target path is not a regular file: {target_path}"
        )

    if not os.access(target_path, os.R_OK):
        raise PermissionError(
            f"Target file is not readable: {target_path}"
        )

    return ["-iL", str(target_path)]


def get_target_description(targets: list[str]):
    if len(targets) != 1:
        return ", ".join(targets)

    target_path = Path(targets[0])

    if not target_path.exists():
        return targets[0]

    return f"target file: {target_path}"

#---------- Target handling ----------#


#---------- Nmap ----------#

def run_nmap_scan(
    scan_name: str,
    scan_options: list[str],
    target_arguments: list[str],
    output_prefix: Path,
    skip_host_discovery: bool
) -> None:
    """Execute an Nmap scan and validate its XML output."""

    command = [NMAP_LOCATION]

    if skip_host_discovery:
        command.append("-Pn")

    command.extend(scan_options)
    command.extend(["-oA", str(output_prefix)])

    resolved_targets = resolve_targets(target_arguments)
    command.extend(resolved_targets)

    write_to_log_file(
        f"Starting {scan_name} scan with command {shlex.join(command)}"
    )

    try:
        subprocess.run(command, check=True)

    except (OSError, subprocess.CalledProcessError) as error:
        write_to_log_file(f"{scan_name} scan failed: {error}")
        raise

    xml_output_file = Path(f"{output_prefix}.xml")

    if not xml_output_file.is_file():
        error_message = (
            f"{scan_name} scan completed but XML output was not found: {xml_output_file}"
        )
        write_to_log_file(error_message)
        raise RuntimeError(error_message)

    write_to_log_file(f"{scan_name} scan completed successfully")
    write_to_log_file(f"XML output: {xml_output_file}")


def run_discovery_scans(args: argparse.Namespace) -> None:
    """Execute UDP and TCP discovery scans concurrently."""

    output_dir = args.output_dir
    output_dir.mkdir(parents=True, exist_ok=True)

    target_description = get_target_description(args.target)

    write_to_log_file(
        f"Starting parallel TCP and UDP discovery scans on {target_description}"
    )
    write_to_log_file(f"Output directory: {output_dir}")

    if args.s:
        scans = {
            "UDP discovery": {
                "scan_options": [
                    "-sU", "--top-ports", "1000",
                    "-T2", "--open", "--reason"
                ],
                "output_prefix": output_dir / "discovery_udp"
            },
            "TCP discovery": {
                "scan_options": [
                    "-sS", "-p-",
                    "-T2", "--open", "--reason"
                ],
                "output_prefix": output_dir / "discovery_tcp"
            }
        }
    else:
        scans = {
            "UDP discovery": {
                "scan_options": [
                    "-sU", "--top-ports", "1000",
                    "--min-rate", "4000", "--open", "--reason"
                ],
                "output_prefix": output_dir / "discovery_udp"
            },
            "TCP discovery": {
                "scan_options": [
                    "-sS", "-p-",
                    "--min-rate", "6000", "--open", "--reason"
                ],
                "output_prefix": output_dir / "discovery_tcp"
            }
        }

    failures = []

    with concurrent.futures.ThreadPoolExecutor(
        max_workers=len(scans)
    ) as executor:

        futures = {
            executor.submit(
                run_nmap_scan,
                scan_name,
                scan["scan_options"],
                args.target,
                scan["output_prefix"],
                args.pn
            ): scan_name

            for scan_name, scan in scans.items()
        }

        for future in concurrent.futures.as_completed(futures):
            scan_name = futures[future]

            try:
                future.result()

            except (OSError, subprocess.CalledProcessError, RuntimeError) as error:
                failures.append(f"{scan_name}: {error}")

    if failures:
        raise RuntimeError(
            "One or more discovery scans failed:\n"
            + "\n".join(failures)
        )

    write_to_log_file("All discovery scans completed successfully")


#---------- Nmap ----------#


#---------- Main ----------#

def main(args: argparse.Namespace) -> int:
    global LOG_FILENAME, NMAP_LOCATION

    LOG_FILENAME = args.log

    try:
        check_root_privileges()
        init_log_file()

        try:
            NMAP_LOCATION = check_nmap_availability()

            now_str = datetime.datetime.now().strftime(
                "%Y-%m-%d_%H-%M-%S"
            )
            args.output_dir = Path(f"{args.output_dir}_{now_str}")

            run_discovery_scans(args)

        finally:
            end_log_file()

    except (ValueError, OSError, RuntimeError) as error:
        print(f"Error: {error}", file=sys.stderr)
        return 1

    return 0


#---------- Main ----------#


#---------- Main call and argparse init ----------#

def parse_arguments() -> argparse.Namespace:
    """Parse command-line arguments."""

    parser = argparse.ArgumentParser(
        description="Harmony network scanner."
    )

    parser.add_argument(
        "-l",
        "--log",
        type=Path,
        default=Path("./harmony.log"),
        help="Path to the log file (default: ./harmony.log).",
    )

    parser.add_argument(
        "-t",
        "--target",
        nargs="+",
        required=True,
        help="Target IP, hostname, network, or a file containing targets.",
    )

    parser.add_argument(
        "-o",
        "--output-dir",
        type=Path,
        default=Path("./output"),
        help="Base directory for Nmap output files (default: ./output).",
    )

    parser.add_argument(
        "-Pn",
        dest="pn",
        action="store_true",
        help="Skip Nmap host discovery.",
    )

    parser.add_argument(
        "-s",
        dest="s",
        action="store_true",
        help="Use a slower, more conservative scan profile.",
    )

    return parser.parse_args()


if __name__ == "__main__":
    args = parse_arguments()
    sys.exit(main(args))

#---------- Main call and argparse init ----------#
