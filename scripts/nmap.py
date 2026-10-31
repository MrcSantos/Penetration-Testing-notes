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
import xml.etree.ElementTree as ET
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


def get_target_description(targets: list[str]) -> str:
    """Return a readable description of the requested targets."""

    if len(targets) != 1:
        return ", ".join(targets)

    target_path = Path(targets[0])

    if not target_path.exists():
        return targets[0]

    return f"target file: {target_path}"


#---------- Target handling ----------#


#---------- XML parsing and service summaries ----------#

def parse_ports_from_host(host: ET.Element[str]) -> list[int]:
    ports_for_host = []
    for port in host.findall("./ports/port"):
        state = port.find("state")
        if state is None or state.get("state") != "open":
            continue

        port_id = port.get("portid")
        if port_id is None:
            continue

        try:
            ports_for_host.append(int(port_id))
        except ValueError:
            continue

    return sorted(set(ports_for_host))

def parse_addresses_from_host(host: ET.Element[str]) -> list[str]:
    addresses = []

    for address in host.findall("address"):
        address_value = address.get("addr")
        addresses.append(address_value)

    return addresses

def parse_hostnames_from_host(host: ET.Element[str]) -> list[str]:
    hostnames = []

    for hostname_object in host.findall("./hostnames/hostname"):
        hostname_value = hostname_object.get("name")
        hostnames.append(hostname_value)

    return sorted(set(hostnames))

def parse_discovered_ports(xml_file: Path) -> dict[str, list[int]]:
    """Return each host's confirmed open ports for the requested protocol."""

    if not xml_file.is_file():
        raise FileNotFoundError(f"Nmap XML output was not found: {xml_file}")

    try:
        root = ET.parse(xml_file).getroot()
    except ET.ParseError as error:
        raise ValueError(f"Invalid Nmap XML in {xml_file}: {error}") from error

    parsed_xml_dict = {}

    for host in root.findall("host"):
        status = host.find("status")
        if status is not None and status.get("state") != "up":
            continue

        addresses = parse_addresses_from_host(host)
        if not addresses:
            continue

        ports_for_host = parse_ports_from_host(host)
        if not ports_for_host:
            continue

        hostnames = parse_hostnames_from_host(host)

        for hostname in hostnames:
            parsed_xml_dict[hostname] = ports_for_host

        for address in addresses:
            parsed_xml_dict[address] = ports_for_host

    return parsed_xml_dict


def write_service_summary(
    discovered_services: dict[str, list[int]],
    output_file: Path
) -> None:
    """Write unique host:port pairs to a service summary file."""

    entries = sorted(
        f"[{host}]:{port}" if ":" in host else f"{host}:{port}"
        for host, ports in discovered_services.items()
        for port in ports
    )

    with output_file.open("w", encoding="utf-8") as summary_file:
        for entry in entries:
            summary_file.write(f"{entry}\n")

    write_to_log_file(
        f"Wrote {len(entries)} service entries to {output_file}",
        write_timestamp=False
    )


def generate_services_summary(output_dir: Path) -> dict[str, dict[str, list[int]]]:
    """Parse discovery XML and write the TCP and UDP service summaries."""

    udp_services = parse_discovered_ports(
        output_dir / "discovery_udp.xml",
    )
    tcp_services = parse_discovered_ports(
        output_dir / "discovery_tcp.xml",
    )

    write_service_summary(udp_services, output_dir / "services_UDP.txt")
    write_service_summary(tcp_services, output_dir / "services_TCP.txt")

    return {"udp": udp_services, "tcp": tcp_services}


#---------- XML parsing and service summaries ----------#


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
            f"{scan_name} scan completed but XML output was not found: "
            f"{xml_output_file}"
        )
        write_to_log_file(error_message)
        raise RuntimeError(error_message)

    write_to_log_file(f"{scan_name} scan completed successfully")
    write_to_log_file(f"XML output: {xml_output_file}")


def run_udp_script_scan(
    host: str,
    ports: list[int],
    script_categories: str,
    output_dir: Path
) -> None:
    """Run a UDP script scan against one host's discovered open UDP ports."""

    if not ports:
        write_to_log_file(f"Skipping UDP script scan for {host}: no open UDP ports")
        return

    output_prefix = output_dir / f"udp_scripts_{host.replace(':', '_')}"
    port_list = ",".join(str(port) for port in sorted(set(ports)))

    command = [
        NMAP_LOCATION,
        "-Pn",
        "-sU",
        "-p", port_list,
        "--script", script_categories,
        "-oA", str(output_prefix),
        host
    ]

    write_to_log_file(
        f"Starting UDP script scan for {host} on ports {port_list} "
        f"with scripts {script_categories}"
    )
    write_to_log_file(f"Command: {shlex.join(command)}")

    try:
        subprocess.run(command, check=True)
    except (OSError, subprocess.CalledProcessError) as error:
        write_to_log_file(f"UDP script scan failed for {host}: {error}")
        raise

    xml_output_file = Path(f"{output_prefix}.xml")
    if not xml_output_file.is_file():
        error_message = (
            f"UDP script scan for {host} completed but XML output was not found: "
            f"{xml_output_file}"
        )
        write_to_log_file(error_message)
        raise RuntimeError(error_message)

    write_to_log_file(f"UDP script scan completed successfully for {host}")
    write_to_log_file(f"XML output: {xml_output_file}")


def run_udp_script_scans(
    discovered_udp_services: dict[str, list[int]],
    args: argparse.Namespace
) -> None:
    """Run one UDP script scan per host with confirmed open UDP ports."""

    if args.s:
        script_categories = "default,safe"
    else:
        script_categories = "default,discovery,safe,auth,vuln"

    hosts_to_scan = {
        host: ports
        for host, ports in discovered_udp_services.items()
        if ports
    }

    if not hosts_to_scan:
        write_to_log_file(
            "No confirmed open UDP ports found; skipping UDP script scans"
        )
        return

    failures = []

    with concurrent.futures.ThreadPoolExecutor(
        max_workers=min(len(hosts_to_scan), 4)
    ) as executor:
        futures = {
            executor.submit(
                run_udp_script_scan,
                host,
                ports,
                script_categories,
                args.output_dir
            ): host
            for host, ports in hosts_to_scan.items()
        }

        for future in concurrent.futures.as_completed(futures):
            host = futures[future]
            try:
                future.result()
            except (OSError, subprocess.CalledProcessError, RuntimeError) as error:
                failures.append(f"{host}: {error}")

    if failures:
        raise RuntimeError(
            "One or more UDP script scans failed:\n" + "\n".join(failures)
        )

    write_to_log_file("All UDP script scans completed successfully")


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
            "One or more discovery scans failed:\n" + "\n".join(failures)
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

            now_str = datetime.datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
            args.output_dir = Path(f"{args.output_dir}_{now_str}")

            run_discovery_scans(args)

            discovered_services = generate_services_summary(args.output_dir)
            run_udp_script_scans(discovered_services["udp"], args)

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
