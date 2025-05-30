# Real-Time Intrusion Detection System (NIDS)  
![Python](https://img.shields.io/badge/Python-3.10-blue) ![Scapy](https://img.shields.io/badge/Scapy-NetworkSniffer-yellow) ![Sklearn](https://img.shields.io/badge/ML-IsolationForest-green) ![Platform](https://img.shields.io/badge/Cross--Platform-Windows%2C%20Linux%2C%20macOS-blueviolet) ![Status](https://img.shields.io/badge/Project-Complete-brightgreen)

This project is a **Real-Time Intrusion Detection System (NIDS)** built using Python. It captures live network traffic, analyzes packet features, detects suspicious behavior using both **signature-based** and **anomaly-based (ML)** techniques, and logs security alerts with detailed metadata.

A **Network Intrusion Detection System (NIDS)** monitors packets flowing through a network interface in real-time, aiming to identify malicious traffic such as port scans, SYN floods, or unknown anomalies.

> ⚠️ **Note:** This project is educational. You are responsible for ensuring legal and ethical use of this tool. Do not run it on public or institutional networks without permission.

---

## 📑 Table of Contents

- [Features](#features)
- [Tech Stack](#tech-stack)
- [Installation](#installation)
- [Environment Configuration](#environment-configuration)
- [Running the System](#running-the-system)
- [Project Structure & File Roles](#project-structure--file-roles)
- [Acknowledgements](#acknowledgements)
- [License](#license)

---

## Features

- Real-time packet capture using `scapy`
- Anomaly detection using `IsolationForest`
- Signature-based detection (e.g., SYN floods, port scans)
- Feature extraction from TCP/IP flows
- Logs alerts to structured log files

---

## Tech Stack

- **Python 3.10**
- **Scapy** – Packet sniffing and decoding
- **scikit-learn** – Machine learning (IsolationForest)
- **python-dotenv** – Environment variable management
- **Npcap** (for Windows users) – Required for packet sniffing

---

## Installation

### 1. Clone the repository
```bash
git clone https://github.com/otuemre/RealTimeNIDS.git
cd RealTimeNIDS
```

### 2. Install dependencies
```bash
pip install -r requirements.txt
```

### 3. Install Npcap (Windows Only)
- Download and install from: [https://nmap.org/npcap/](https://nmap.org/npcap/)
- ✅ Enable "WinPcap API-compatible Mode" during setup

> 💡 **Linux/macOS users:** Scapy uses native `libpcap`, usually pre-installed. If not, install via `apt` (Linux) or `brew` (macOS).

---

## Environment Configuration

Create a `.env` file in the project root:
```env
INTERFACE=\Device\NPF_{YOUR_INTERFACE_ID}
```

To find your interface, run this:
```python
from scapy.all import get_if_list
print(get_if_list())
```

---

## Running the System

```bash
python intrusion_detection_system.py
```

You’ll see:
- ✅ Packet collection
- ✅ IsolationForest model training
- ✅ Real-time threat detection and alert logging

---

## Project Structure & File Roles

| File                            | Purpose                                                                                                            |
|---------------------------------|--------------------------------------------------------------------------------------------------------------------|
| `packet_capture.py`             | Captures packets in real time using `scapy`. Filters for IP + TCP packets and queues them for analysis.            |
| `traffic_analyzer.py`           | Extracts statistical features from each packet (e.g., packet size, rate, flow duration, TCP flags).                |
| `detection_engine.py`           | Detects threats using both signature-based rules and anomaly detection via IsolationForest.                        |
| `alert_system.py`               | Logs alerts in structured format to a log file. Critical alerts are emphasized.                                    |
| `intrusion_detection_system.py` | Main runner. Wires all components: sniffing, feature extraction, detection, and alerting. Includes training logic. |
| `.env`                          | Stores the selected network interface ID (never push this to GitHub).                                              |
| `requirements.txt`              | Contains required dependencies for the system.                                                                     |

---

## Acknowledgements

- Original project inspiration from FreeCodeCamp tutorial: [Build a Real-Time Intrusion Detection System with Python](https://www.freecodecamp.org/news/build-a-real-time-intrusion-detection-system-with-python/#heading-building-the-detection-engine)

---

## License

This project is licensed under the [MIT License](LICENSE.md). You are free to use, modify, and distribute it responsibly.

