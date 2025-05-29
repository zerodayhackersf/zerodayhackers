#!/usr/bin/env python3
import os
import platform
import subprocess
import sys
from time import sleep

# Check if nmap is installed
def check_nmap_installation():
    try:
        subprocess.run(["nmap", "--version"], stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=True)
        return True
    except (subprocess.CalledProcessError, FileNotFoundError):
        return False

# Install nmap based on platform
def install_nmap():
    system = platform.system().lower()
    
    if system == "linux":
        # Check if it's Android (Termux)
        if "android" in platform.platform().lower():
            print("\n[+] Installing Nmap in Termux...")
            subprocess.run(["pkg", "install", "nmap", "-y"], check=True)
        else:
            print("\n[+] Installing Nmap on Linux...")
            subprocess.run(["sudo", "apt-get", "update"], check=True)
            subprocess.run(["sudo", "apt-get", "install", "nmap", "-y"], check=True)
    elif system == "windows":
        print("\n[!] Please download and install Nmap from https://nmap.org/download.html")
        print("After installation, add Nmap to your system PATH and run this script again.")
        sys.exit(1)
    else:
        print("\n[!] Unsupported operating system. Please install Nmap manually.")
        sys.exit(1)

# Display banner
def show_banner():
    banner = """
    the quites you become, the more you are able to hear
    """
    print(banner)

# Display scan options
def show_options():
    options = """
    select target option
    01. Quick Scan (Top 100 ports)
    02. Full Port Scan (All 65535 ports)
    03. OS Detection
    04. Service Version Detection
    05. Aggressive Scan
    06. Ping Scan (Host Discovery)
    07. UDP Scan
    08. Custom Scan (Enter your own Nmap arguments)
    09. Exit
    """
    print(options)

# Execute nmap scan
def run_nmap_scan(target, scan_type):
    scan_commands = {
        1: f"nmap -T4 -F {target}",  # Quick Scan
        2: f"nmap -T4 -p- {target}",  # Full Port Scan
        3: f"nmap -T4 -O {target}",   # OS Detection
        4: f"nmap -T4 -sV {target}",  # Service Version
        5: f"nmap -T4 -A {target}",    # Aggressive Scan
        6: f"nmap -T4 -sn {target}",   # Ping Scan
        7: f"nmap -T4 -sU {target}",   # UDP Scan
    }
    
    if scan_type in scan_commands:
        command = scan_commands[scan_type]
    elif scan_type == 8:
        custom_args = input("\nEnter your Nmap arguments (e.g., -sS -p 80,443 -Pn): ")
        command = f"nmap {custom_args} {target}"
    else:
        print("\n[!] Invalid scan type selected.")
        return
    
    print(f"\n Executing: {command} \n")
    
    try:
        # Run the command and capture output in real-time
        process = subprocess.Popen(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        
        # Print output in real-time
        while True:
            output = process.stdout.readline()
            if output == '' and process.poll() is not None:
                break
            if output:
                print(output.strip())
        
        # Check for errors
        stderr = process.stderr.read()
        if stderr:
            print(f"\n Error:  {stderr.strip()}")
        
    except KeyboardInterrupt:
        print("\n [!] Scan interrupted by user.")
    except Exception as e:
        print(f"\n[!] Error during scan: {e}")

# Main function
def main():
    # Check if nmap is installed
    if not check_nmap_installation():
        print("\n[!] Nmap is not installed on your system.")
        install = input("[?] Do you want to install Nmap now? (y/n): ").lower()
        if install == 'y':
            install_nmap()
            if not check_nmap_installation():
                print("\n[!] Installation failed. Please install Nmap manually.")
                sys.exit(1)
        else:
            print("\n[!] Nmap is required for this tool to work. Exiting...")
            sys.exit(1)
    
    show_banner()
    
    while True:
        try:
            show_options()
            choice = input("\n Enter your Target (1-8)$  ")
            
            if choice == '9':
                print("\n [+] Exiting Nmap Scanner. Goodbye!")
                break
            
            try:
                scan_type = int(choice)
                if scan_type < 1 or scan_type > 8:
                    print("\n [!] Please enter a number between 1 and 9.")
                    continue
                
                target = input("\n Enter target IP/hostname (e.g., 192.168.1.1 or example.com): ").strip()
                if not target:
                    print("\n [!] Target cannot be empty.")
                    continue
                
                run_nmap_scan(target, scan_type)
                
            except ValueError:
                print("\n [!] Please enter a valid number.")
            
            # Ask if user wants to perform another scan
            another = input("\n Do you want to perform another scan? (y/n): ").lower()
            if another != 'y':
                print("\n [+] Exiting Nmap Scanner. Goodbye!")
                break
                
        except KeyboardInterrupt:
            print("\n [!] Operation cancelled by user.")
            break

if __name__ == "__main__":
    main()