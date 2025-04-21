#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Network Scanner with Terminal UI for Raspberry Pi OS (and other Linux systems)
"""

import ipaddress
import subprocess
import threading
import time
import queue
import curses
import socket
import re
import os
import argparse
from datetime import datetime
import traceback  # Import traceback for error handling

# Class for the network scanner
class NetworkScanner:
    def __init__(self):
        self.active_hosts = {}
        self.scan_queue = queue.Queue()
        self.result_queue = queue.Queue()
        self.scan_active = False
        self.worker_threads = []
        self.scan_thread = None
        self.stop_event = threading.Event()

    def get_default_gateway(self):
        """Gets the default gateway IP address"""
        try:
            # First attempt: /proc/net/route (works well on many Linux systems)
            with open('/proc/net/route') as f:
                for line in f.readlines():
                    fields = line.strip().split()
                    # Destination '00000000' is the default route
                    if len(fields) > 2 and fields[1] == '00000000':
                        # Gateway address is in hex, little-endian. Convert to dotted decimal.
                        gateway_hex = fields[2]
                        gateway_int = int(gateway_hex, 16)
                        # Reverse bytes (little-endian to big-endian for IP)
                        gateway_ip = socket.inet_ntoa(gateway_int.to_bytes(4, byteorder='little'))
                        return gateway_ip
        except FileNotFoundError:
             pass # /proc/net/route doesn't exist, try the next method
        except Exception as e:
            # Log any unexpected errors while reading /proc/net/route
            # print(f"Error reading /proc/net/route: {e}") # Optional: add logging
            pass

        # Second attempt: 'ip route' command (more modern and often more reliable)
        try:
            result = subprocess.run(['ip', 'route', 'show', 'default'],
                                    capture_output=True, text=True, check=True, timeout=2)
            match = re.search(r'default via (\d+\.\d+\.\d+\.\d+)', result.stdout)
            if match:
                return match.group(1)
        except (subprocess.SubprocessError, FileNotFoundError, subprocess.TimeoutExpired) as e:
            # Log any errors executing 'ip route'
            # print(f"Error executing 'ip route': {e}") # Optional: add logging
            pass

        return None # Could not find gateway

    def get_local_ip(self):
        """Gets the local IP address used for outgoing connections"""
        s = None
        try:
            # Create a UDP socket (no real connection needed)
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            # Connect to an external address (doesn't need to be reachable)
            # Google DNS is a common choice, but any external IP works
            s.connect(("8.8.8.8", 80))
            local_ip = s.getsockname()[0]
            return local_ip
        except socket.error as e:
            # print(f"Could not determine local IP via socket: {e}") # Optional: logging
            # Fallback: try hostname (less reliable for *the* local IP)
            try:
                return socket.gethostbyname(socket.gethostname())
            except socket.gaierror:
                return None # Could not find IP using any method
        finally:
            if s:
                s.close()


    def get_netmask(self):
        """Gets the netmask of the interface with the local IP"""
        local_ip = self.get_local_ip()
        if not local_ip:
            return "255.255.255.0"  # Default fallback

        try:
            # Use 'ip addr show' to get interface details
            result = subprocess.run(['ip', '-o', '-f', 'inet', 'addr', 'show'],
                                    capture_output=True, text=True, check=True, timeout=2)

            for line in result.stdout.strip().split('\n'):
                # Search for the line containing the local IP address
                if f' {local_ip}/' in line:
                    # Extract the prefix length (CIDR)
                    match = re.search(rf'{re.escape(local_ip)}/(\d+)', line)
                    if match:
                        prefix_len = int(match.group(1))
                        # Convert prefix length to netmask
                        # Creates a hostmask (all bits 1)
                        host_bits = 32 - prefix_len
                        netmask_int = ((1 << 32) - 1) ^ ((1 << host_bits) - 1)
                        netmask = socket.inet_ntoa(netmask_int.to_bytes(4, byteorder='big'))
                        return netmask

            return "255.255.255.0"  # Fallback if IP was found, but CIDR couldn't be parsed
        except (subprocess.SubprocessError, FileNotFoundError, subprocess.TimeoutExpired) as e:
            # print(f"Error executing 'ip addr': {e}") # Optional: logging
            return "255.255.255.0"  # Fallback on error

    def get_network_range(self):
        """Determines the network IP range (CIDR notation) based on local IP and netmask"""
        local_ip = self.get_local_ip()
        netmask = self.get_netmask()

        if local_ip and netmask:
            try:
                # Use ipaddress module for correct network calculation
                ip_interface = ipaddress.IPv4Interface(f"{local_ip}/{netmask}")
                network = ip_interface.network
                return str(network) # Returns CIDR notation, e.g., "192.168.1.0/24"
            except ValueError as e:
                # print(f"Error calculating network range: {e}") # Optional: logging
                pass # Continue to fallback

        # Fallback if IP or netmask couldn't be found, or on error
        return "192.168.1.0/24"

    def ping_host(self, ip):
        """Pings a host to see if it is active. Uses OS-specific ping."""
        try:
            # Build the ping command.
            # -c 1: send 1 packet
            # -W 1: wait max 1 second for reply
            # On Windows it's -n 1 (count) and -w 1000 (timeout ms)
            if os.name == 'nt': # Windows
                 command = ["ping", "-n", "1", "-w", "1000", str(ip)]
            else: # Linux/macOS
                 command = ["ping", "-c", "1", "-W", "1", str(ip)]

            # Execute the command, hide output
            result = subprocess.run(
                command,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                timeout=1.5 # Also give the process itself a timeout
            )
            # Return code 0 means success (host is reachable)
            return result.returncode == 0
        except (subprocess.SubprocessError, subprocess.TimeoutExpired):
            # Error during ping execution or timeout
            return False
        except Exception:
            # Other unexpected errors
            return False

    def get_mac_address(self, ip):
        """Tries to find the MAC address of an IP address on the local network."""
        ip_str = str(ip)

        # 1. Try via ARP table (/proc/net/arp on Linux)
        if os.path.exists('/proc/net/arp'):
            try:
                with open('/proc/net/arp', 'r') as f:
                    # Read lines, skip header
                    lines = f.readlines()[1:]
                    for line in lines:
                        fields = line.split()
                        # Columns: IP address, HW type, Flags, HW address, Mask, Device
                        if len(fields) >= 4 and fields[0] == ip_str:
                            mac = fields[3]
                            # Check if MAC is valid (not incomplete or 00:00:...)
                            if mac != "00:00:00:00:00:00" and len(mac) == 17:
                                return mac
            except Exception:
                 # Error reading ARP table, continue to next method
                 pass

        # 2. Try via `ip neigh` (more modern alternative to `arp -a` on Linux)
        try:
            result = subprocess.run(['ip', 'neigh', 'show', ip_str],
                                    capture_output=True, text=True, timeout=1)
            if result.returncode == 0 and result.stdout:
                match = re.search(r'lladdr\s+([0-9a-fA-F:]+)', result.stdout)
                if match:
                    mac = match.group(1)
                    if mac != "00:00:00:00:00:00" and len(mac) == 17:
                         return mac
        except (subprocess.SubprocessError, FileNotFoundError, subprocess.TimeoutExpired):
            pass # Command not found, timeout, or other error

        # 3. Try via `arp -a` (works on Linux, macOS, Windows)
        #    Often less reliable if the entry isn't already in the cache
        #    and might require the host to be pinged first.
        try:
            result = subprocess.run(['arp', '-a', ip_str], capture_output=True, text=True, timeout=1)
            # Output format varies by OS. Search for MAC address pattern.
            # Example Linux/macOS: ? (192.168.1.1) at 12:34:56:78:9a:bc [ether] on eth0
            # Example Windows: 192.168.1.1     12-34-56-78-9a-bc     dynamic
            match = re.search(r'([0-9a-fA-F]{2}[:-]){5}[0-9a-fA-F]{2}', result.stdout, re.IGNORECASE)
            if match:
                mac = match.group(0).replace('-',':').lower()
                if mac != "00:00:00:00:00:00":
                    return mac
        except (subprocess.SubprocessError, FileNotFoundError, subprocess.TimeoutExpired):
             pass

        # 4. Try via `arp-scan` (Linux, requires root/sudo and separate installation)
        #    This is more active and effective, but requires more permissions/setup.
        #    Only run if other methods fail and we are root or can use sudo.
        #    Check if the command exists first.
        try:
            which_result = subprocess.run(["which", "arp-scan"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            if which_result.returncode == 0:
                # Try to execute arp-scan. --localnet scans the detected local network.
                # --quiet reduces output. --numeric shows IPs instead of hostnames.
                # Timeout is important, can take long on large networks.
                 arp_scan_cmd = ["sudo", "arp-scan", "--localnet", "--quiet", "--numeric", "--timeout=500", "--retry=1"]
                 # Target the scan specifically at the target IP for efficiency
                 arp_scan_cmd.append(ip_str)

                 result = subprocess.run(
                     arp_scan_cmd,
                     capture_output=True,
                     text=True,
                     timeout=2 # Timeout for the whole process
                 )
                 # Parse output (typically: IP\tMAC\tVendor)
                 for line in result.stdout.strip().split('\n'):
                     fields = line.split('\t')
                     if len(fields) >= 2 and fields[0] == ip_str:
                         mac = fields[1]
                         if mac != "00:00:00:00:00:00" and len(mac) == 17:
                             return mac
        except (subprocess.SubprocessError, FileNotFoundError, subprocess.TimeoutExpired):
            pass # arp-scan not available, no sudo rights, timeout, or other error.

        # If no method works
        return "Unknown"

    def worker(self):
        """Worker thread that processes IP addresses from the scan_queue."""
        while not self.stop_event.is_set():
            try:
                # Get an IP address from the queue. Wait max 0.1s.
                ip = self.scan_queue.get(block=True, timeout=0.1)

                # 1. Ping the host to see if it's active
                is_active = self.ping_host(ip)

                if is_active:
                    # 2. Try to resolve hostname
                    hostname = "Unknown"
                    try:
                        # getfqdn tries to find a Fully Qualified Domain Name
                        # This can sometimes take long or fail, hence the timeout attempt
                        # However, socket.getfqdn doesn't have a built-in timeout parameter.
                        # We can try gethostbyaddr, which might fail faster.
                        try:
                            # socket.setdefaulttimeout(0.5) # Setting global timeout (risky)
                            hostname = socket.gethostbyaddr(str(ip))[0]
                        except socket.herror:
                            # Hostname could not be found via reverse lookup
                            hostname = "Unknown"
                        except Exception:
                             # Other socket errors
                            hostname = "Unknown"
                        # finally:
                            # socket.setdefaulttimeout(None) # Reset global timeout

                        # If gethostbyaddr fails or returns IP, try getfqdn still
                        if hostname == str(ip) or hostname == "Unknown":
                            try:
                                 # This can still take long without timeout
                                 hostname_fqdn = socket.getfqdn(str(ip))
                                 if hostname_fqdn != str(ip): # Only use if different from IP
                                     hostname = hostname_fqdn
                            except Exception:
                                # getfqdn also fails, stick with "Unknown" or original IP
                                if hostname == str(ip): hostname = "Unknown"

                    except Exception:
                        hostname = "Unknown" # Catch all remaining errors

                    # 3. Try to find MAC address
                    mac_address = self.get_mac_address(ip)

                    # 4. Add the result to the result_queue
                    self.result_queue.put((str(ip), hostname, mac_address, True))

                # Mark task as completed in the scan_queue
                self.scan_queue.task_done()

            except queue.Empty:
                # Queue is empty, worker can pause briefly or stop if event is set
                continue
            except Exception as e:
                # Log unexpected error in worker
                # print(f"Error in worker thread: {e}") # Optional
                # Make sure task_done is called, even on error,
                # otherwise scan_queue.join() might block.
                try:
                     self.scan_queue.task_done()
                except ValueError: # Can happen if task_done was already called
                     pass
                continue


    def start_scan(self, network_range_cidr):
        """Starts a network scan for the specified IP range (CIDR)."""
        if self.scan_active:
            return False # Scan is already active

        try:
            # Validate the network range
            network = ipaddress.IPv4Network(network_range_cidr, strict=False)
        except ValueError:
            # print(f"Invalid network range: {network_range_cidr}") # Optional
            return False # Cannot start with invalid range

        self.stop_event.clear() # Reset the stop signal
        self.scan_active = True
        self.active_hosts.clear() # Clear previous results

        # Empty the queues for the new scan
        while not self.scan_queue.empty():
            try: self.scan_queue.get_nowait()
            except queue.Empty: break
        while not self.result_queue.empty():
            try: self.result_queue.get_nowait()
            except queue.Empty: break

        # Create and start worker threads
        self.worker_threads = []
        num_workers = min(50, max(10, network.num_addresses // 5)) # Dynamic number of workers
        for _ in range(num_workers):
            thread = threading.Thread(target=self.worker, daemon=True)
            # daemon=True ensures threads stop when main program exits
            thread.start()
            self.worker_threads.append(thread)

        # Start the thread that fills the scan_queue
        self.scan_thread = threading.Thread(
            target=self._scan_thread_func,
            args=(network,), # Pass the validated network object
            daemon=True
        )
        self.scan_thread.start()

        return True # Scan started successfully

    def _scan_thread_func(self, network):
        """Thread function that fills the scan_queue with IP addresses."""
        try:
            total_ips = network.num_addresses
            # print(f"Scanning network {network} ({total_ips} addresses)...") # Optional

            # Add all *host* IP addresses to the scan queue
            # .hosts() skips network and broadcast addresses
            for ip in network.hosts():
                if self.stop_event.is_set():
                    # print("Scan stopped by user (filling queue).") # Optional
                    break # Stop filling if stop signal is given
                self.scan_queue.put(ip)

            # Wait until all items in the queue are processed by workers,
            # unless the scan is stopped prematurely.
            # scan_queue.join() waits until task_done() is called for each item.
            while not self.scan_queue.empty() and not self.stop_event.is_set():
                 time.sleep(0.1) # Actively wait instead of join() to check stop_event

            if not self.stop_event.is_set():
                 # print("All IPs placed in queue. Waiting for workers...") # Optional
                 self.scan_queue.join() # Wait for workers to finish
                 # print("Scan completed.") # Optional


        except Exception as e:
            # print(f"Error in scan thread: {e}") # Optional
            pass # Log the error optionally
        finally:
            # Mark scan as inactive, regardless of how the thread ends
            self.scan_active = False
            # print("Scan thread finished.") # Optional


    def stop_scan(self):
        """Stops the current scan and waits for threads."""
        if not self.scan_active and not self.stop_event.is_set():
            # If scan is already stopped or never started, do nothing
            # Also check stop_event in case stop was called but active isn't False yet
            return

        # print("Stop signal given...") # Optional
        self.stop_event.set() # Signal all threads to stop

        # Empty the scan queue to prevent workers from starting new tasks
        while not self.scan_queue.empty():
            try:
                self.scan_queue.get_nowait()
                self.scan_queue.task_done() # Mark as done so join() doesn't block
            except queue.Empty:
                break
            except ValueError: # task_done() can fail if queue changes internally
                pass

        # Wait for the scan_thread (which fills the queue) to stop
        if self.scan_thread and self.scan_thread.is_alive():
            # print("Waiting for scan_thread...") # Optional
            self.scan_thread.join(timeout=1.0) # Give it max 1 second

        # Wait for all worker threads to stop
        # print(f"Waiting for {len(self.worker_threads)} worker threads...") # Optional
        for thread in self.worker_threads:
            if thread.is_alive():
                thread.join(timeout=1.0) # Give each worker max 1 second

        self.scan_active = False # Explicitly set status to False
        # print("Scan stopped and threads cleaned up.") # Optional


    def process_results(self):
        """Processes results from the result_queue and updates active_hosts."""
        newly_found = []
        try:
            while True: # Get all available results
                ip, hostname, mac, is_active = self.result_queue.get_nowait()
                if is_active:
                    # Add to active_hosts (dictionary) and newly_found (list)
                    if ip not in self.active_hosts:
                         newly_found.append({'ip': ip, 'hostname': hostname, 'mac': mac})
                    # Update/overwrite host info (e.g., hostname resolution might change)
                    self.active_hosts[ip] = {'hostname': hostname, 'mac': mac}
                # Mark task as completed in result_queue
                self.result_queue.task_done()
        except queue.Empty:
            # No more results in the queue
            pass
        except Exception as e:
             # print(f"Error processing results: {e}") # Optional
             pass

        return newly_found # Returns only the *new* hosts found this time


# Class for the Terminal UI
class TerminalUI:
    def __init__(self, scanner):
        self.scanner = scanner
        self.stdscr = None
        self.current_network = self.scanner.get_network_range() # Get initial network
        self.scan_results_list = [] # List for display, sorted by IP
        self.selected_index = 0
        self.scroll_offset = 0
        self.mode = "main"  # main, details, help, input, confirm
        self.selected_host_ip = None # Only keep track of IP for detail view
        self.last_scan_time = None
        self.message = ""
        self.message_timeout = 0

    def run(self):
        """Starts the terminal UI loop."""
        try:
            # Initialize curses
            self.stdscr = curses.initscr()
            curses.start_color()
            curses.use_default_colors() # Use terminal default background (-1)
            curses.cbreak() # React to keys instantly (no Enter needed)
            curses.noecho() # Don't echo pressed keys
            self.stdscr.keypad(True) # Allow special keys (arrows, etc.)
            curses.curs_set(0)  # Hide cursor

            # Define colors (if terminal supports colors)
            if curses.has_colors():
                curses.init_pair(1, curses.COLOR_GREEN, -1)  # Active hosts
                curses.init_pair(2, curses.COLOR_BLACK, curses.COLOR_CYAN)  # Selected row (Cyan background)
                curses.init_pair(3, curses.COLOR_RED, -1)    # Error messages/Status
                curses.init_pair(4, curses.COLOR_YELLOW, -1) # Headers/Titles
                curses.init_pair(5, curses.COLOR_WHITE, curses.COLOR_BLUE) # Menu bar
                curses.init_pair(6, curses.COLOR_MAGENTA, -1) # Details labels

            self.stdscr.timeout(100)  # Non-blocking getch(), check every 100ms

            # Main loop
            while True:
                # 1. Process new results from the scanner
                new_hosts = self.scanner.process_results()
                if new_hosts:
                    # Add new hosts to the display list
                    for host_info in new_hosts:
                         # Ensure we don't add duplicates (although process_results should handle this)
                         if not any(item['ip'] == host_info['ip'] for item in self.scan_results_list):
                              self.scan_results_list.append(host_info)
                    # Sort the list by IP address (numerically)
                    self.scan_results_list.sort(key=lambda x: ipaddress.ip_address(x['ip']))

                # 2. Draw the current screen based on the mode
                if self.mode == "main":
                    self._draw_main_screen()
                elif self.mode == "details":
                    self._draw_details_screen()
                elif self.mode == "help":
                    self._draw_help_screen()
                # Input/Confirm dialogs are handled directly and draw themselves

                # 3. Process user input
                ch = self.stdscr.getch() # Get keystroke (or -1 on timeout)

                # Global keys
                if ch == ord('q'):
                    if self._confirm_dialog("Are you sure you want to quit? (y/n)"):
                        break # Exit the main loop
                    else:
                         continue # Stay in the loop, redraw screen
                elif ch == ord('?'):
                     self.mode = "help"
                     continue # Go to help mode
                elif ch == 27: # ESC key
                    if self.mode == "details" or self.mode == "help":
                         self.mode = "main" # Back to main menu
                         continue
                    elif self.mode == "main":
                         if self._confirm_dialog("Are you sure you want to quit? (y/n)"):
                             break # Exit the main loop
                         else:
                             continue # Stay in the loop

                # Mode-specific keys
                if self.mode == "main":
                    self._handle_main_input(ch)
                elif self.mode == "details":
                    self._handle_details_input(ch)
                elif self.mode == "help":
                    self._handle_help_input(ch) # Any key closes help

        except Exception as e:
            # Catch unexpected errors, restore terminal and print error
            self._cleanup_curses()
            print("--- Critical Error in UI ---")
            print(f"Error: {e}")
            traceback.print_exc()
            print("--------------------------")
            print("Terminal UI stopped.")

        finally:
            # Ensure the scanner stops and terminal is restored on exit
            self.scanner.stop_scan()
            self._cleanup_curses()

    def _cleanup_curses(self):
        """Restores the terminal to its normal state."""
        if self.stdscr:
            curses.nocbreak()
            self.stdscr.keypad(False)
            curses.echo()
            curses.endwin()
            self.stdscr = None # Mark that curses is no longer active

    def _get_color(self, pair_number, attributes=curses.A_NORMAL):
        """Helper to get color pair, with fallback if colors don't work."""
        if curses.has_colors():
            return curses.color_pair(pair_number) | attributes
        elif pair_number == 2: # Specific fallback for selection without colors
            return curses.A_REVERSE # Use reverse video for selection
        else:
            return attributes # No specific color, only attributes (bold, etc.)

    def _addstr_safe(self, y, x, text, attr=0):
        """Adds a string, but catches curses errors (e.g., writing outside screen)."""
        try:
            height, width = self.stdscr.getmaxyx()
            # Check if position is within screen bounds
            if 0 <= y < height and 0 <= x < width:
                 # Truncate text so it fits starting from position x
                 max_len = width - x
                 self.stdscr.addstr(y, x, text[:max_len], attr)
            # Else: do nothing (prevents crash)
        except curses.error:
            pass # Ignore curses errors (e.g., writing to bottom-right corner)


    def _draw_main_screen(self):
        """Draws the main screen with the list of found hosts."""
        self.stdscr.erase() # Clear previous screen
        height, width = self.stdscr.getmaxyx()

        # Title
        title = " Network Scanner "
        title_attr = self._get_color(4, curses.A_BOLD)
        self._addstr_safe(0, (width - len(title)) // 2, title, title_attr)

        # Network Info
        net_info = f"Network: {self.current_network}"
        gw = self.scanner.get_default_gateway()
        lip = self.scanner.get_local_ip()
        if gw: net_info += f" | GW: {gw}"
        if lip: net_info += f" | Local: {lip}"
        self._addstr_safe(1, 0, net_info)

        # Scan Status
        status_line = "Status: "
        scan_state = "Idle"
        if self.scanner.scan_active:
            scan_state = "Scanning..."
        elif self.last_scan_time:
            scan_state = f"Scan finished ({self.last_scan_time.strftime('%H:%M:%S')})"
        status_line += scan_state + f" | Hosts: {len(self.scan_results_list)}"
        self._addstr_safe(2, 0, status_line)

        # Message (if present and not expired)
        if self.message and time.time() < self.message_timeout:
             msg_attr = self._get_color(3) # Red for messages
             self._addstr_safe(3, 0, self.message, msg_attr)
        elif self.message: # Clear message if timeout passed
             self.message = ""

        # Headers for the list
        header_y = 4
        header = "{:<18} {:<30} {:<17}".format(" IP Address", " Hostname", " MAC Address")
        header_attr = self._get_color(4, curses.A_BOLD) # Yellow, bold
        self._addstr_safe(header_y, 0, header, header_attr)
        self._addstr_safe(header_y + 1, 0, "-" * (width-1))

        # Calculate visible area for the list
        list_start_y = header_y + 2
        list_height = height - list_start_y - 1 # Room for menu at the bottom
        if list_height <= 0: return # Not enough space to show list

        # Scrolling logic
        if self.selected_index < self.scroll_offset:
             self.scroll_offset = self.selected_index
        if self.selected_index >= self.scroll_offset + list_height:
             self.scroll_offset = self.selected_index - list_height + 1

        # Display the results in the list
        list_end_y = list_start_y + list_height
        items_to_display = self.scan_results_list[self.scroll_offset : self.scroll_offset + list_height]

        for idx, item_info in enumerate(items_to_display):
            display_y = list_start_y + idx
            if display_y >= list_end_y: break # Stop if we go outside the area

            ip = item_info.get('ip', 'N/A')
            hostname = item_info.get('hostname', 'N/A')
            mac = item_info.get('mac', 'N/A')

            # Shorten hostname if necessary
            display_hostname = hostname if len(hostname) <= 28 else hostname[:25] + "..."
            # Shortening MAC is usually not needed

            row_text = "{:<18} {:<30} {:<17}".format(f" {ip}", f" {display_hostname}", f" {mac}")

            # Determine attributes (normal or selected)
            list_index = self.scroll_offset + idx
            if list_index == self.selected_index:
                attr = self._get_color(2) # Selected (e.g., reverse/cyan bg)
            else:
                attr = self._get_color(1) # Normal (e.g., green)

            self._addstr_safe(display_y, 0, row_text, attr)

        # Menu at the bottom
        menu_y = height - 1
        menu_text = " [s]Scan [r]Refresh [n]Network [Enter]Details [?]Help [q]Quit "
        menu_attr = self._get_color(5) # Blue background
        self._addstr_safe(menu_y, 0, menu_text.ljust(width), menu_attr)

        self.stdscr.refresh() # Show everything on the screen

    def _handle_main_input(self, ch):
        """Handles input specific to the main screen."""
        if ch == ord('s'):
            if self.scanner.scan_active:
                self.scanner.stop_scan()
                self.show_message("Scan stopped.", 2)
            else:
                # Clear old results for new scan
                self.scan_results_list = []
                self.scanner.active_hosts.clear()
                self.selected_index = 0
                self.scroll_offset = 0
                if self.scanner.start_scan(self.current_network):
                    self.last_scan_time = datetime.now()
                    self.show_message("Scan started...", 2)
                else:
                    self.show_message("Could not start scan (invalid network?).", 3)

        elif ch == ord('r'): # Refresh (stop current, clear list, start again)
            self.scanner.stop_scan() # Stop any running scan first
            self.scan_results_list = []
            self.scanner.active_hosts.clear()
            self.selected_index = 0
            self.scroll_offset = 0
            if self.scanner.start_scan(self.current_network):
                self.last_scan_time = datetime.now()
                self.show_message("List cleared, scan restarted...", 2)
            else:
                 self.show_message("Could not start scan (invalid network?).", 3)


        elif ch == ord('n'): # Enter new network
            new_network = self._input_dialog(
                 "Enter new network range (e.g., 192.168.1.0/24):",
                 self.current_network
            )
            if new_network and new_network != self.current_network:
                try:
                    # Validate the entered network
                    ipaddress.IPv4Network(new_network, strict=False)
                    self.current_network = new_network
                    self.scanner.stop_scan() # Stop current scan
                    self.scan_results_list = [] # Clear results
                    self.scanner.active_hosts.clear()
                    self.selected_index = 0
                    self.scroll_offset = 0
                    self.show_message(f"Network set to {self.current_network}. Start scan with 's'.", 4)
                except ValueError:
                    self.show_message(f"Invalid network format: {new_network}", 3)
            # Trigger redraw
            self.stdscr.clear()


        elif ch == curses.KEY_UP:
            if self.selected_index > 0:
                self.selected_index -= 1

        elif ch == curses.KEY_DOWN:
             if self.selected_index < len(self.scan_results_list) - 1:
                 self.selected_index += 1

        elif ch == curses.KEY_PPAGE: # Page Up
            height, _ = self.stdscr.getmaxyx()
            page_size = max(1, height - 8) # Estimated list height, at least 1
            self.selected_index = max(0, self.selected_index - page_size)


        elif ch == curses.KEY_NPAGE: # Page Down
            height, _ = self.stdscr.getmaxyx()
            page_size = max(1, height - 8) # Estimated list height, at least 1
            max_index = len(self.scan_results_list) - 1
            if max_index < 0: max_index = 0 # Handle empty list
            self.selected_index = min(max_index, self.selected_index + page_size)


        elif ch == ord('\n') or ch == curses.KEY_ENTER: # Enter
            if self.scan_results_list and 0 <= self.selected_index < len(self.scan_results_list):
                self.selected_host_ip = self.scan_results_list[self.selected_index]['ip']
                self.mode = "details" # Switch to detail mode
            else:
                 self.show_message("Select a host first.", 2)


    def _draw_details_screen(self):
        """Draws the details screen for the selected host."""
        self.stdscr.erase()
        height, width = self.stdscr.getmaxyx()

        host_info = self.scanner.active_hosts.get(self.selected_host_ip)
        if not host_info:
            self.mode = "main" # Host no longer found? Back to main menu.
            self.show_message("Host details unavailable.", 2)
            return

        ip = self.selected_host_ip
        hostname = host_info.get('hostname', 'N/A')
        mac = host_info.get('mac', 'N/A')

        # Title
        title = f" Details for {ip} "
        title_attr = self._get_color(4, curses.A_BOLD)
        self._addstr_safe(0, (width - len(title)) // 2, title, title_attr)
        self._addstr_safe(1, 0, "=" * (width-1), self._get_color(4))

        # Basic Info
        info_y = 3
        label_attr = self._get_color(6, curses.A_BOLD) # Magenta bold
        self._addstr_safe(info_y, 2, "IP Address:", label_attr)
        self._addstr_safe(info_y, 18, ip)
        self._addstr_safe(info_y + 1, 2, "Hostname:", label_attr)
        self._addstr_safe(info_y + 1, 18, hostname)
        self._addstr_safe(info_y + 2, 2, "MAC Address:", label_attr)
        self._addstr_safe(info_y + 2, 18, mac)

        line = info_y + 4

        # --- Ping Statistics ---
        if line < height - 3:
            self._addstr_safe(line, 0, "Ping (4 packets):", self._get_color(4, curses.A_BOLD))
            line += 1
            try:
                # Use OS-specific ping
                if os.name == 'nt': # Windows
                    ping_cmd = ["ping", "-n", "4", "-w", "1000", ip]
                else: # Linux/macOS
                    ping_cmd = ["ping", "-c", "4", "-W", "1", ip]

                result = subprocess.run(
                    ping_cmd, capture_output=True, text=True, timeout=5
                )
                ping_output = result.stdout.strip() if result.returncode == 0 else result.stderr.strip()
                if not ping_output and result.returncode != 0 :
                    ping_output = "Host unreachable or ping failed."

                for ping_line in ping_output.split('\n'):
                    if line < height - 2: # Room for menu
                        self._addstr_safe(line, 2, ping_line)
                        line += 1
                    else:
                        self._addstr_safe(line, 2, "...") # Too much output
                        line += 1
                        break
            except (subprocess.SubprocessError, subprocess.TimeoutExpired) as e:
                 if line < height - 2:
                     self._addstr_safe(line, 2, f"Ping command failed: {e}")
                     line += 1
            except Exception as e:
                 if line < height - 2:
                     self._addstr_safe(line, 2, f"Error pinging: {e}")
                     line += 1

        line += 1 # Extra empty line

        # --- Quick Port Scan (Top ~10 ports) ---
        if line < height - 3:
            self._addstr_safe(line, 0, "Quick Port Scan:", self._get_color(4, curses.A_BOLD))
            line += 1
            common_ports = [21, 22, 23, 25, 53, 80, 110, 135, 139, 443, 445, 3389, 8080]
            open_ports_found = []
            port_scan_line = line

            # Run port checks in parallel for speed? Maybe overkill for few ports.
            # Sticking to sequential for simplicity here.
            ports_scanned = 0
            for port in common_ports:
                if port_scan_line >= height - 2:
                    self._addstr_safe(port_scan_line, 2, "...") # More ports scanned than fit
                    port_scan_line += 1
                    break

                port_status = "Closed"
                sock = None
                try:
                    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    sock.settimeout(0.3)  # Short timeout per port
                    result = sock.connect_ex((ip, port))
                    if result == 0:
                        port_status = "Open"
                        open_ports_found.append(port)
                except socket.error:
                    port_status = "Error" # Cannot reach/scan port
                finally:
                    if sock: sock.close()

                if port_status == "Open":
                     try:
                         service = socket.getservbyport(port, 'tcp')
                     except OSError:
                         service = "unknown"
                     self._addstr_safe(port_scan_line, 2, f"- Port {port:<5} ({service}): {port_status}", self._get_color(1)) # Green for open
                     port_scan_line += 1
                # Optional: show closed ports? Can clutter the UI.
                # else:
                #    self._addstr_safe(port_scan_line, 2, f"- Port {port:<5}: {port_status}")
                #    port_scan_line += 1
                ports_scanned += 1

            if not open_ports_found and port_scan_line < height - 2:
                 self._addstr_safe(port_scan_line, 2, "No common open ports found.")
                 port_scan_line += 1

            line = port_scan_line # Update the current line position

        # Menu at the bottom
        menu_y = height - 1
        menu_text = " [p]Nmap Scan [t]Traceroute [Esc]Back [q]Quit "
        menu_attr = self._get_color(5)
        self._addstr_safe(menu_y, 0, menu_text.ljust(width), menu_attr)

        self.stdscr.refresh()

    def _run_external_command(self, command, title):
         """Helper to run external commands outside of curses."""
         self._cleanup_curses() # Temporarily close curses
         print(f"\n--- {title} for {self.selected_host_ip} ---")
         print(f"Command: {' '.join(command)}")
         print("------------------------------------------------")
         try:
             # Run the command and show output directly
             subprocess.run(command, check=True)
             print("------------------------------------------------")
             print("Command finished.")
         except FileNotFoundError:
             print(f"\nError: Command '{command[0]}' not found.")
             # Line 903: Check the 'ï' character below carefully
             print("Make sure the program is installed and in your PATH.")
             # Show installation hint if known
             if command[0] == "nmap": print("Install with: sudo apt-get install nmap (or package manager)")
             if command[0] == "traceroute": print("Install with: sudo apt-get install traceroute (or package manager)")
             if command[0] == "arp-scan": print("Install with: sudo apt-get install arp-scan (or package manager)")

         except subprocess.CalledProcessError as e:
             print(f"\nError: Command failed with return code {e.returncode}.")
         except subprocess.TimeoutExpired:
              print("\nError: Command timed out.")
         except Exception as e:
              print(f"\nUnexpected error: {e}")

         print("\nPress Enter to return to the scanner...")
         input() # Wait for user

         # Reinitialize curses
         self.stdscr = curses.initscr()
         curses.start_color()
         curses.use_default_colors()
         curses.cbreak()
         curses.noecho()
         self.stdscr.keypad(True)
         curses.curs_set(0)
         self.stdscr.timeout(100)
         self.stdscr.clear() # Clear screen before redraw
         self.stdscr.refresh()


    def _handle_details_input(self, ch):
        """Handles input specific to the details screen."""
        if not self.selected_host_ip:
             self.mode = "main"
             return

        ip = self.selected_host_ip

        if ch == ord('p'): # Nmap scan
            # Check if sudo is needed first (often for -sS, -O etc.)
            # For a basic -sV scan it's not always needed, but recommended.
            command = ["sudo", "nmap", "-sV", "-T4", ip] # -sV = service version, -T4 = faster timing
            self._run_external_command(command, "Nmap Service Scan")


        elif ch == ord('t'): # Traceroute
             # Usually works without sudo
             if os.name == 'nt': # Windows
                 command = ["tracert", ip]
             else: # Linux/macOS
                 command = ["traceroute", ip]
             self._run_external_command(command, "Traceroute")

        # Esc key is handled in the main loop

    def _draw_help_screen(self):
        """Draws the help screen."""
        self.stdscr.erase()
        height, width = self.stdscr.getmaxyx()

        # Title
        title = " Network Scanner Help "
        title_attr = self._get_color(4, curses.A_BOLD)
        self._addstr_safe(0, (width - len(title)) // 2, title, title_attr)
        self._addstr_safe(1, 0, "=" * (width-1), self._get_color(4))

        # Help Text
        help_lines = [
            "",
            " Main Screen:",
            "   s       : Start/Stop the network scan",
            "   r       : Refresh (clear list, restart scan)",
            "   n       : Set a new network range to scan (CIDR)",
            "   Enter   : Show details of the selected host",
            "   Up/Down : Navigate through the list",
            "   PgUp/Dn : Scroll quickly through the list",
            "",
            " Details Screen:",
            "   p       : Run Nmap scan (requires sudo & nmap)",
            "   t       : Run Traceroute (requires traceroute)",
            "   Esc     : Back to main screen",
            "",
            " General:",
            "   ?       : Show this help screen",
            "   q       : Quit the application (asks confirmation)",
            "   Esc     : Back / Quit (asks confirmation)",
            "",
            " Tips:",
            "   - The first scan might take a while.",
            "   - External tools (nmap, traceroute) must be installed.",
            "   - Some actions (nmap, arp-scan) require sudo/root privileges.",
        ]

        line_y = 2
        for line in help_lines:
            if line_y < height - 1: # Room for menu
                self._addstr_safe(line_y, 1, line)
                line_y += 1
            else:
                break

        # Menu at the bottom
        menu_y = height - 1
        menu_text = " Press any key to go back "
        menu_attr = self._get_color(5)
        self._addstr_safe(menu_y, 0, menu_text.ljust(width), menu_attr)

        self.stdscr.refresh()

    def _handle_help_input(self, ch):
        """Handles input for the help screen (any key closes)."""
        if ch != -1: # Ignore timeout events (-1)
             self.mode = "main" # Go back to main menu

    def _create_dialog_window(self, height, width):
         """Creates a new curses window for dialogs."""
         term_height, term_width = self.stdscr.getmaxyx()
         start_y = (term_height - height) // 2
         start_x = (term_width - width) // 2
         win = curses.newwin(height, width, start_y, start_x)
         win.box()
         return win

    def _input_dialog(self, prompt, default=""):
        """Shows a dialog for text input."""
        self.mode = "input" # Set mode to give input focus
        dialog_height = 5
        dialog_width = max(len(prompt) + 4, 60) # Min width 60
        dialog_width = min(dialog_width, self.stdscr.getmaxyx()[1] - 2) # Max width terminal

        dialog_win = self._create_dialog_window(dialog_height, dialog_width)
        dialog_win.addstr(1, 2, prompt)

        # Create a subwindow for the input box
        input_win = dialog_win.derwin(1, dialog_width - 4, 3, 2)

        # Turn cursor on, echo on for this window
        curses.curs_set(1)
        curses.echo()
        input_win.keypad(True) # Allow special keys in input

        input_text = default
        input_win.addstr(0, 0, input_text)
        input_win.refresh()

        # Input loop (curses.textpad.Textbox is more complex, manual loop is ok)
        while True:
             ch = input_win.getch()

             if ch == ord('\n') or ch == curses.KEY_ENTER:
                 break # Confirm input
             elif ch == 27: # ESC
                 input_text = None # Cancel input
                 break
             elif ch == curses.KEY_BACKSPACE or ch == 127 or ch == 8: # Backspace (platform dependent)
                 if len(input_text) > 0:
                     input_text = input_text[:-1]
                     # Clear input window and redraw
                     input_win.clear()
                     input_win.addstr(0, 0, input_text)
                     input_win.refresh()
             elif 32 <= ch <= 126: # Printable ASCII characters
                 if len(input_text) < dialog_width - 5: # Prevent overflow
                     input_text += chr(ch)
                     # Add character (echo already does this, but refresh is needed)
                     input_win.addstr(0, len(input_text) - 1, chr(ch))
                     input_win.refresh()
             # Ignore other keys

        # Restore settings
        curses.curs_set(0)
        curses.noecho()
        # input_win doesn't need to be cleared, whole screen will be redrawn

        del dialog_win # Clean up window
        self.stdscr.touchwin() # Make sure main window is active again
        self.stdscr.refresh()
        self.mode = "main" # Back to main mode

        return input_text # Returns None on cancel (ESC)


    def _confirm_dialog(self, prompt):
        """Shows a yes/no confirmation dialog."""
        self.mode = "confirm"
        dialog_height = 5
        dialog_width = max(len(prompt) + 12, 40) # Room for prompt and (y/n)
        dialog_width = min(dialog_width, self.stdscr.getmaxyx()[1] - 2)

        dialog_win = self._create_dialog_window(dialog_height, dialog_width)
        dialog_win.addstr(1, (dialog_width - len(prompt)) // 2, prompt)
        dialog_win.addstr(3, (dialog_width - 10) // 2, "[Y]es / [N]o")
        dialog_win.keypad(True) # Allow keys
        dialog_win.timeout(-1) # Wait indefinitely for input

        result = False
        while True:
             ch = dialog_win.getch()
             if ch == ord('y') or ch == ord('Y'):
                 result = True
                 break
             elif ch == ord('n') or ch == ord('N') or ch == 27: # N or Esc
                 result = False
                 break
             # Ignore other keys

        del dialog_win
        self.stdscr.touchwin()
        self.stdscr.refresh()
        self.mode = "main" # Always return to main after confirm

        return result

    def show_message(self, message, timeout=3):
        """Shows a message at the bottom of the screen for a duration."""
        self.message = message
        self.message_timeout = time.time() + timeout


# Functions outside the classes
def check_tool(tool_name):
     """Checks if an external command is available in PATH."""
     try:
         # Use 'which' on Unix-like systems, 'where' on Windows
         command = "where" if os.name == 'nt' else "which"
         result = subprocess.run([command, tool_name],
                                 stdout=subprocess.DEVNULL,
                                 stderr=subprocess.DEVNULL,
                                 check=True)
         return True
     except (FileNotFoundError, subprocess.CalledProcessError):
          return False

def setup_dependencies():
    """Checks for external tools that are needed or useful."""
    print("Checking for required/recommended tools...")
    required = ["ping"] # Absolutely needed
    # On Windows, arp and traceroute might be 'arp' and 'tracert'
    recommended_unix = ["arp", "ip", "traceroute", "nmap", "arp-scan"]
    recommended_win = ["arp", "ipconfig", "tracert", "nmap"] # nmap needs separate install
    recommended = recommended_win if os.name == 'nt' else recommended_unix

    missing_required = [tool for tool in required if not check_tool(tool)]
    missing_recommended = [tool for tool in recommended if not check_tool(tool)]

    if missing_required:
        print("\n--- Critical Error ---")
        print("The following required commands were not found in your PATH:")
        for tool in missing_required:
            print(f" - {tool}")
        print("The script cannot function correctly without these tools.")
        # Try to provide installation hints (Debian/Ubuntu focus)
        if os.name != 'nt':
            if "ping" in missing_required: print("Install 'iputils-ping'")
        else:
             print("Ensure the system's network tools are included in the PATH environment variable.")
        print("---------------------")
        return False # Cannot continue

    if missing_recommended:
        print("\n--- Recommendation ---")
        print("The following tools were not found and are recommended for full functionality:")
        packages = []
        for tool in missing_recommended:
            print(f" - {tool}")
            if os.name != 'nt': # Linux/macOS hints
                if tool == "arp": packages.append("net-tools")
                if tool == "ip": packages.append("iproute2")
                if tool == "traceroute": packages.append("traceroute") # or inetutils-traceroute
                if tool == "nmap": packages.append("nmap")
                if tool == "arp-scan": packages.append("arp-scan")
            else: # Windows hints
                 if tool == "nmap": packages.append("nmap (download from nmap.org)")
                 # Others are usually built-in, might just not be in PATH
        unique_packages = sorted(list(set(packages)))
        if unique_packages:
            if os.name != 'nt':
                 print("\nYou can install them with (e.g., on Debian/Ubuntu):")
                 print(f"sudo apt update && sudo apt install {' '.join(unique_packages)}")
            else:
                 print("\nYou may need to install or add the location of these tools to your PATH:")
                 print(f"{', '.join(unique_packages)}")
        print("--------------------\n")
        # Don't ask for installation, just continue.

    # Check sudo privileges (needed for arp-scan and nmap -sS/-O on Unix)
    if os.name != 'nt':
        try:
             # A quick, non-destructive sudo check
             result = subprocess.run(["sudo", "-n", "true"], stderr=subprocess.DEVNULL)
             if result.returncode != 0:
                  print("--- Warning ---")
                  print("It seems you don't have immediate sudo privileges (password needed).")
                  print("Some functions (Nmap, arp-scan) might ask for a password or fail.")
                  print("---------------\n")
        except FileNotFoundError:
             print("--- Warning ---")
             print("'sudo' command not found. Advanced scans might not be available.")
             print("---------------\n")
    else: # Windows privilege check is more complex, skip for now
        pass

    print("Dependency check completed.\n")
    return True # All essentials are present


def parse_arguments():
    """Processes command-line arguments."""
    parser = argparse.ArgumentParser(
        description='Network Scanner with Terminal UI.',
        epilog='Example: python scanner.py -n 192.168.0.0/24 --auto-scan'
    )
    parser.add_argument(
        '-n', '--network',
        help='Network range to scan (e.g., 192.168.1.0/24). Auto-detects if not provided.'
    )
    parser.add_argument(
        '-a', '--auto-scan',
        action='store_true',
        help='Automatically start a scan on launch.'
    )
    return parser.parse_args()


def main():
    """Main function of the program."""
    # 1. Check dependencies
    if not setup_dependencies():
        print("Necessary dependencies are missing. Program will exit.")
        return 1 # Exit code 1 for error

    # 2. Process command-line arguments
    args = parse_arguments()

    # 3. Create scanner and UI instances
    scanner = NetworkScanner()
    ui = TerminalUI(scanner) # UI gets initial network itself

    # 4. Override network if specified via argument
    if args.network:
        try:
            # Validate network argument
            ipaddress.IPv4Network(args.network, strict=False)
            ui.current_network = args.network
            print(f"Network set via argument: {ui.current_network}")
        except ValueError:
            print(f"Invalid network specified via argument: {args.network}")
            print(f"Using auto-detected network: {ui.current_network}")

    # 5. Start auto-scan if requested
    if args.auto_scan:
        print("Starting automatic scan...")
        if scanner.start_scan(ui.current_network):
             ui.last_scan_time = datetime.now()
             ui.show_message("Automatic scan started...", 2) # Message for UI
        else:
             print("Could not start automatic scan.") # Message for console

    # 6. Start the UI loop
    ui.run()

    print("\nNetwork scanner finished.")
    return 0 # Exit code 0 for success


if __name__ == "__main__":
    exit_code = 1 # Default exit code on unexpected error
    try:
        exit_code = main()
    except KeyboardInterrupt:
        print("\nProgram interrupted by user (Ctrl+C).")
        # Cleanup happens in ui.run() finally block
        exit_code = 0 # Normal exit on Ctrl+C
    except Exception as e:
        # Catch any other unexpected errors
        print("\n--- Unexpected Main Error ---")
        print(f"Error: {e}")
        traceback.print_exc() # Print full traceback
        print("-----------------------------")
        exit_code = 1 # Error exit code

    # Ensure terminal is always restored, even after a crash in main()
    # This is an extra safety net in case _cleanup_curses was not reached.
    try:
        if curses.isendwin() is False: # Check if curses is still active
             curses.nocbreak()
             curses.keypad(False)
             curses.echo()
             curses.endwin()
             print("(Terminal restored after error)")
    except Exception:
         pass # Avoid errors during cleanup itself

    exit(exit_code)