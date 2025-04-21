# Terminal Network Scanner

A Python script that scans the local network for active hosts and displays them in a terminal user interface (TUI) built with `curses`. Designed primarily for Linux systems like Raspberry Pi OS, but should work on other Linux distributions and potentially macOS/Windows with the right dependencies.

## Features

* **Auto-Detection:** Automatically detects the local IP, netmask, gateway, and network range to scan.
* **Terminal UI:** Uses the `curses` library to provide an interactive terminal interface.
* **Host Discovery:** Pings hosts in the specified network range to find active devices.
* **Hostname Resolution:** Attempts to resolve hostnames for found IP addresses.
* **MAC Address Lookup:** Tries to find MAC addresses using various methods (ARP table, `ip neigh`, `arp`, `arp-scan`).
* **Host Details:** View basic details (IP, Hostname, MAC), ping statistics, and results of a quick port scan for common ports (21, 22, 23, 25, 53, 80, 110, 135, 139, 443, 445, 3389, 8080).
* **External Tool Integration:** Provides options in the details view to launch `nmap` (service scan) and `traceroute` against the selected host (requires these tools and potentially `sudo`).
* **Customizable Scan Range:** Manually specify a different network range (CIDR notation) to scan.
* **Background Scanning:** Uses threading to perform scans without freezing the UI.

## Dependencies

### Python
* Python 3.x
* Built-in modules: `ipaddress`, `subprocess`, `threading`, `time`, `queue`, `curses`, `socket`, `re`, `os`, `argparse`, `datetime`, `traceback`. (The `curses` module might not be available by default on Windows).

### External Command-Line Tools
These tools are called by the script and should be installed on your system and available in your PATH.

* **Required:**
    * `ping` (Usually provided by `iputils-ping` on Debian/Ubuntu)
* **Recommended for full functionality:**
    * `ip` (Usually provided by `iproute2` on Debian/Ubuntu)
    * `arp` (Usually provided by `net-tools` on Debian/Ubuntu)
    * `traceroute` (Package name `traceroute` on Debian/Ubuntu)
    * `nmap` (Package name `nmap` on Debian/Ubuntu) - Needed for the 'Nmap Scan' option.
    * `arp-scan` (Package name `arp-scan` on Debian/Ubuntu) - Used as a fallback for MAC address discovery, often requires `sudo`.

The script will check for these tools on startup.

## Installation

1.  **Clone the repository:**
    ```bash
    git clone [https://github.com/your-username/your-repository-name.git](https://github.com/your-username/your-repository-name.git)
    cd your-repository-name
    ```
    (Replace `your-username/your-repository-name` with your actual GitHub details)

2.  **Install Dependencies (Example for Debian/Ubuntu):**
    Make sure `ping` is installed. For recommended tools:
    ```bash
    sudo apt update
    sudo apt install iproute2 net-tools traceroute nmap arp-scan python3
    ```
    *Note: `python3` might already be installed.*

3.  **Make the script executable (Optional):**
    ```bash
    chmod +x network_scanner.py
    ```

## Usage

Run the script from your terminal:

```bash
python3 network_scanner.py