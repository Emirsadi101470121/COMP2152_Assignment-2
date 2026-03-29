"""
Author: Emir Sadi
Assignment: #2
Description: Port Scanner — A tool that scans a target machine for open network ports
"""

import socket
import threading
import sqlite3
import os
import platform
import datetime

print("Python Version:", platform.python_version())
print("Operating System:", os.name)

# Dictionary that maps common port numbers to their service names
common_ports = {
    21: "FTP",
    22: "SSH",
    23: "Telnet",
    25: "SMTP",
    53: "DNS",
    80: "HTTP",
    110: "POP3",
    143: "IMAP",
    443: "HTTPS",
    3306: "MySQL",
    3389: "RDP",
    8080: "HTTP-Alt"
}


class NetworkTool:
    def __init__(self, target):
        self.__target = target

    # Q3: What is the benefit of using @property and @target.setter?
    # Using @property and @target.setter allows us to control how the target attribute
    # is accessed and modified without exposing the private __target directly.
    # The setter lets us add validation logic (like rejecting empty strings) before
    # setting the value, which protects the object's internal state from invalid data.
    @property
    def target(self):
        return self.__target

    @target.setter
    def target(self, value):
        if value == "":
            print("Error: Target cannot be empty")
        else:
            self.__target = value

    def __del__(self):
        print("NetworkTool instance destroyed")


# Q1: How does PortScanner reuse code from NetworkTool?
# PortScanner inherits from NetworkTool using class PortScanner(NetworkTool),
# which means it automatically gets the __target attribute, the @property getter,
# the @target.setter with validation, and the __del__ destructor from NetworkTool.
# For example, PortScanner does not redefine the target getter/setter — it
# calls super().__init__(target) to set it up through the parent class constructor.
class PortScanner(NetworkTool):
    def __init__(self, target):
        super().__init__(target)
        self.scan_results = []
        self.lock = threading.Lock()

    def __del__(self):
        print("PortScanner instance destroyed")
        super().__del__()

    def scan_port(self, port):
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(1)
            # Q4: What would happen without try-except here?
            # Without try-except, if the scanner tries to connect to an unreachable
            # machine or a refused connection occurs, Python would raise an unhandled
            # exception like ConnectionRefusedError or socket.timeout that would crash
            # the entire program immediately.
            # With try-except, we gracefully catch these errors and continue scanning
            # the remaining ports without interrupting the whole scan operation.
            result = sock.connect_ex((self.target, port))
            status = "Open" if result == 0 else "Closed"
            service_name = common_ports.get(port, "Unknown")
            self.lock.acquire()
            self.scan_results.append((port, status, service_name))
            self.lock.release()
        except socket.error as e:
            print(f"Error scanning port {port}: {e}")
        finally:
            sock.close()

    def get_open_ports(self):
        return [result for result in self.scan_results if result[1] == "Open"]

    # Q2: Why do we use threading instead of scanning one port at a time?
    # Threading allows multiple ports to be scanned simultaneously rather than
    # waiting for each connection attempt to time out before moving to the next.
    # Without threads, scanning 1024 ports with a 1-second timeout each would take
    # over 17 minutes in the worst case since closed ports wait the full timeout period.
    # With threading, all ports are scanned concurrently, completing in roughly
    # 1-2 seconds total regardless of how many ports are being scanned.
    def scan_range(self, start_port, end_port):
        threads = []
        for port in range(start_port, end_port + 1):
            t = threading.Thread(target=self.scan_port, args=(port,))
            threads.append(t)
        for t in threads:
            t.start()
        for t in threads:
            t.join()


def save_results(target, results):
    try:
        conn = sqlite3.connect("scan_history.db")
        cursor = conn.cursor()
        cursor.execute("""CREATE TABLE IF NOT EXISTS scans (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            target TEXT,
            port INTEGER,
            status TEXT,
            service TEXT,
            scan_date TEXT
        )""")
        for result in results:
            cursor.execute(
                "INSERT INTO scans (target, port, status, service, scan_date) VALUES (?, ?, ?, ?, ?)",
                (target, result[0], result[1], result[2], str(datetime.datetime.now()))
            )
        conn.commit()
        conn.close()
        print("Results saved to database.")
    except sqlite3.Error as e:
        print(f"Database error: {e}")


def load_past_scans():
    try:
        conn = sqlite3.connect("scan_history.db")
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM scans")
        rows = cursor.fetchall()
        if not rows:
            print("No past scans found.")
        else:
            for row in rows:
                print(f"[{row[5]}] {row[1]} : Port {row[2]} ({row[4]}) - {row[3]}")
        conn.close()
    except sqlite3.Error:
        print("No past scans found.")


if __name__ == "__main__":
    try:
        target = input("Enter target IP address (default 127.0.0.1): ").strip()
        if target == "":
            target = "127.0.0.1"
    except ValueError:
        target = "127.0.0.1"

    start_port = None
    while start_port is None:
        try:
            start_port = int(input("Enter start port (1-1024): ").strip())
            if start_port < 1 or start_port > 1024:
                print("Port must be between 1 and 1024.")
                start_port = None
        except ValueError:
            print("Invalid input. Please enter a valid integer.")

    end_port = None
    while end_port is None:
        try:
            end_port = int(input("Enter end port (1-1024): ").strip())
            if end_port < 1 or end_port > 1024:
                print("Port must be between 1 and 1024.")
                end_port = None
            elif end_port < start_port:
                print("End port must be greater than or equal to start port.")
                end_port = None
        except ValueError:
            print("Invalid input. Please enter a valid integer.")

    scanner = PortScanner(target)
    print(f"Scanning {target} from port {start_port} to {end_port}...")
    scanner.scan_range(start_port, end_port)

    open_ports = scanner.get_open_ports()
    print(f"\n--- Scan Results for {target} ---")
    for port_info in open_ports:
        print(f"Port {port_info[0]}: Open ({port_info[2]})")
    print("------")
    print(f"Total open ports found: {len(open_ports)}")

    save_results(target, scanner.scan_results)

    view_history = input("\nWould you like to see past scan history? (yes/no): ").strip().lower()
    if view_history == "yes":
        load_past_scans()

# Q5: New Feature Proposal
# One feature I would add is an export-to-CSV function that saves scan results
# to a .csv file for easy viewing in spreadsheet tools like Excel.
# It would use a list comprehension to filter only open ports from scan_results
# and write each one as a row: open_rows = [r for r in scan_results if r[1] == "Open"]
# This makes sharing and archiving scan reports much more convenient.
# Diagram: See diagram_101470121.png in the repository root