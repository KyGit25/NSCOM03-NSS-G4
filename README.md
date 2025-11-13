# Visual Network Traffic Analyzer

A simple **network monitoring tool** built with **Python**, **Scapy**, **PyQt5**, and **Matplotlib**.  
It captures packets in real time and shows network activity through graphs and tables.

---

## Features
- Live packet capture using Scapy  
- Shows discovered devices (IP, packets, bytes, timestamps)  
- Real-time charts for:
  - Top Talkers (most active IPs)
  - Protocol Distribution (TCP, UDP, ARP, etc.)
  - Throughput (bytes per second)
- Optional IP filter
- Export captured packets to `.pcap` (for Wireshark)
- Clear/reset stats anytime

---

## Requirements
Install these first:
```bash
pip install PyQt5 matplotlib scapy pandas
```

Python 3.8 or newer is recommended.

---

## How to Run
1. Open a terminal in the project folder.  
2. Run the app:
   ```bash
   python main.py
   ```
3. Select a network interface and click **Start Capture**.  
4. Click **Stop Capture** to end capture or **Export PCAP** to save.

---

## Testing with Wireshark
To verify that your analyzer captures the same packets as Wireshark:
1. **Open Wireshark** and select the same interface used in the analyzer.  
2. **Start both** Wireshark and the Visual Network Traffic Analyzer **at the same time**.  
3. Let them run for a short period (e.g., 30–60 seconds).  
4. **Stop both captures at the same time** if possible.  
5. Compare the number of packets and protocols captured — they should be close or similar.

---

## Interface Overview
| Section | Description |
|----------|-------------|
| **Discovered Devices** | Shows all IPs seen on the network |
| **Top Talkers** | Bar graph of most active IPs |
| **Protocol Distribution** | Pie chart of traffic types |
| **Throughput** | Graph of total bytes over time |
| **Activity Log** | Shows messages and new device detections |

---

## Notes
- On **Windows**, run Python as Administrator.  
- On **Linux/macOS**, use:
  ```bash
  sudo python3 main.py
  ```
- The tool may not detect Wi-Fi interfaces if permissions are restricted.

---

## Author
Created by:<br>
- **Owen San Luis**<br>
- **Kyle Maristela**<br>
- **Evan Andrew Pinca**  
In partial fulfillment of the requirements for NSCOM03 – Network Simulation Study,<br>
De La Salle University (DLSU)
(Visual Network Traffic Analyzer Prototype)
