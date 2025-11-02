# WiFi Manager 🔧

A powerful **Python-based Windows WiFi utility** for network scanning, monitoring, and control.
It provides advanced tools for **ARP spoofing, DNS sniffing, MAC address modification, port scanning**, and other network utilities — all from a clean command-line interface.

![WiFi Manager](terminal.png)

---

## ⚙️ Features

* **WiFi Scanner:** Detect devices connected to your local network (uses `nmap` and `scapy`).
* **ARP Spoofing & DNS Sniffer:** Monitors DNS requests and identifies access to popular social media domains.
* **Port Scanner:** Scans common ports (1–1024) on a target IP and shows open ones.
* **Network Info Display:** Shows IP and MAC information for your physical network interfaces.
* **Device Disconnector:** Disconnects a target device or all devices on the same network.
* **MAC Address Changer:**

  * Set a **custom MAC address** or generate a **random** one.
  * Automatically disables/enables adapters to apply changes.
  * Works via PowerShell with administrative rights.
 
    ![WiFi Manager - Scanner](terminal-scan.png)

---

## Requirements

* **Windows OS**
* **Python 3.9+**
* **Nmap** installed and added to system PATH
  Download: [https://nmap.org/download.html](https://nmap.org/download.html)
* **Required Python modules:**

  ```bash
  pip install scapy
  ```

---

## How to Run

1. Clone the repository:

   ```bash
   git clone https://github.com/yourusername/WiFi-Manager.git
   cd WiFi-Manager
   ```

2. Run the script with administrator privileges:

   ```bash
   python WiFi_Manager.py
   ```

3. Follow the on-screen menu to choose operations:

   ```
   1 - WiFi Scanner
   2 - Arp Spoofing & Sniffer
   3 - Port Scanner
   4 - Your information
   5 - Disconnect devices
   6 - Change Your MAC Address
   ```

---

## ⚠️ Disclaimer

This tool is intended **for educational and network testing purposes only**.
Unauthorized use on networks you don’t own or manage is **illegal**.
Use responsibly.

---

## License

MIT License © 2025 [Ali Emad (asgard)](https://github.com/asgardOP)
