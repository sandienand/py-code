"""
File Name: digicore_port_scanner.py
Created by Sandie Nand
Script is a TCP port scanner tat will identify open ports or a target IP/hostname for a vulnerability assessment.
Date of development: 04-12-2025
"""

import socket
import argparse
import datetime
import re
import sys

# constants
CONNECTION_TIMEOUT = 1.0 # seconds
DATE_TIME_FORMAT = "%d-%m-%Y %H:%M:%S" #Australian date time format
LOG_FILE_PATH = "digicore_scan_log_" + datetime.datetime.now().strftime("%d%m%Y_%H%M%S") + ".txt"

def log_result(message: str) -> None:
    """Logs the given message to the log file with a timestamp."""
    try:
        timestamp = datetime.datetime.now().strftime(DATE_TIME_FORMAT)
        with open(LOG_FILE_PATH, 'a') as f:
            f.write(f"[{timestamp}] {message}\n")
    except IOError as e:
        print(f"[CRITICAL ERROR] Failed to write to log file: {e}")

def get_validated_input() -> tuple[str | None, int | None, int | None]:
    """
    Command-line argument parsing and input validation.
    
    Returns tuple[target_ip, start_port, end_port] or [None, None, None] on failure.
    """
    parser = argparse.ArgumentParser(description="DigiCore TCP Port Scannner - scans a specified port range on a target domain.")
    parser.add_argument("target", help="Target IP address or hostname to scan (eg, 192.168.1.1 or example.com).")
    parser.add_argument("ports", help="Port range (eg 1-1024).")

    try:
        args = parser.parse_args()
    except SystemExit:
        """
        Exit if arguments are missing.
        """
        return None, None, None
    
    # Port Range Validation / Parsing
    if not re.match(r"^\d+-\d+$", args.ports):
        log_result(f"[ERROR] Invalid Port Range Format: '{args.ports}'. Use format 1-1024.")
        print("[ERROR] Invalid port range format. Please use the format 1-1024.")
        return None, None, None

    try:
        start_port, end_port = map(int, args.ports.split('-'))
    except ValueError:
        log_result(f"[ERROR] Port Range contains non-numeric values: '{args.ports}'.")
        print("[ERROR] Port range must contain numeric values only.")
        return None, None, None

    if not (1 <= start_port <= 65535 and 1 <= end_port <= 65535 and start_port <= end_port):
        log_result(f"[ERROR] Port Range out of valid bounds: '{start_port}-{end_port}'.")
        print("[ERROR] Port range must be between 1 and 65535, and start port must be less than or equal to end port.")
        return None, None, None 

    # Target IP/Hostname Validation
    resolved_ip = None
    try:
        resolved_ip = socket.gethostbyname(args.target)
    except socket.gaierror:
        log_result(f"[ERROR] Failed to resolve target hostname: '{args.target}'.")
        print(f"[ERROR] Unable to resolve target hostname: '{args.target}'. Check hostname or IP")
        return None, None, None

    print(f"Target resolved to IP: {resolved_ip}")
    return resolved_ip, start_port, end_port


def attempt_connection(target_ip: str, port: int) -> str:
    """
    Attempts TCP connection to single port.

    Arguments:
        target_ip : Target IP address
        port: TCP port to check

    Returns:
        string indicating if port is open or closed.
    """
    # AF_INET: IPv4, SOCK_STREAM: TCP
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(CONNECTION_TIMEOUT)

    try:
        #attempt connection
        result = sock.connect_ex((target_ip, port))

        if result == 0:
            # Connection successful
            return "OPEN"
        elif result ==111 or result == 10061 or result == 10035:
            return "CLOSED"
        else:
            log_result(f"[WARNING] Port {port} returned code {result}. Treating as ERROR.")
            return "ERROR"
        
    except socket.timeout:
        return "TIMEOUT"
    except socket.error as e:
        log_result(f"[ERROR] Socket error on port {port}: {e}")
        return "ERROR"
    finally:
        sock.close()


def scan_target(target_ip: str, start_port: int, end_port: int) -> None:
    """
    Goes through port range, calls the connection function, and logs results.

    Arguments:
        target_ip : Target IP address
        start_port : Starting port number
        end_port : Ending port number
    """

    print("----------------------------------------------------")
    print(f"\nStarting scan on {target_ip} from port {start_port} to {end_port}")
    print("----------------------------------------------------")
    log_result(f"Starting scan on {target_ip} from port {start_port} to {end_port}.")

    open_ports_count = 0

    for port in range(start_port, end_port + 1):
        sys.stdout.write(f"Checking port {port}...\r")
        sys.stdout.flush()

        status = attempt_connection(target_ip, port)

        if status == "OPEN":
            sys.stdout.write(" " * 50 + "\r")
            sys.stdout.flush()
            print(f"Port {port}: >>> OPEN <<<")
            log_result(f"Port {port}: OPEN")
            open_ports_count += 1
        elif status == "TIMEOUT":
            log_result(f"Port {port}: TIMEOUT (1000ms limit exceeded)")
        elif status == "ERROR":
            log_result(f"Port {port}: ERROR during connection attempt.")
        # Closed ports are not logged to reduce log size

    #final real-time summary
    print(" " * 50, end='\r')  # Clear line
    print("----------------------------------------------------")
    print(f"Scan completed on {target_ip}. Total open ports found: {open_ports_count}")
    print(f'Results and errors/timeouts logged to: {LOG_FILE_PATH}')

if __name__ == "__main__":

    print("\n*** DigiCore TCP Port Scanner ***")

    target_ip, start_port, end_port = get_validated_input()

    if target_ip and start_port is not None and end_port is not None:
        log_result("Input validation successful. Beginning scan.")
        try:
            scan_target(target_ip, start_port, end_port)
        except KeyboardInterrupt:
            print("\nScan interrupted by user. Exiting.")
            log_result("Scan interrupted by user.")
        except Exception as e:
            print(f"\n[CRITICAL ERROR] An unexpected error occurred: {e}")
            log_result(f"[CRITICAL ERROR] An unexpected error occurred: {e}")
        finally:
            log_result("Scan process ended.")
    else:
        if len(sys.argv) == 1:
            print("No command-line arguments provided.")
            print("Usage Example: python digicore_port_scanner.py 192.168.1.1 1-100")
