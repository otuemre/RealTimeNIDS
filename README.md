# Real-Time Network Intrusion Detection System (RealTimeNIDS)  
![Python](https://img.shields.io/badge/Python-3.10-blue) ![Zeek](https://img.shields.io/badge/Zeek-NetworkMonitoring-orange) ![Sklearn](https://img.shields.io/badge/ML-IsolationForest-green) ![Platform](https://img.shields.io/badge/Cross--Platform-Windows%2C%20Linux%2C%20macOS-blueviolet) ![Status](https://img.shields.io/badge/Project-Active-important)

This project is a **Real-Time Network Intrusion Detection System (NIDS)** that monitors network traffic at the **flow level** using **Zeek**, extracts relevant features, and detects threats in real-time using both:

- ✅ **Signature-based detection** (e.g., port scans)
- ✅ **Anomaly-based detection** using a trained **IsolationForest** model

The system is trained on the **CIC-IDS 2018** dataset for realistic attack patterns and supports continuous monitoring via Zeek’s `conn.log`.

> ⚠️ **Important:** This project is for educational and research purposes. Always obtain permission before deploying on real or institutional networks.

---

## 📑 Table of Contents

- [Features](#features)
- [Tech Stack](#tech-stack)
- [Installation](#installation)
- [Zeek Configuration](#zeek-configuration)
- [Running the System](#running-the-system)
- [Project Structure](#project-structure)
- [Future Improvements](#future-improvements)
- [Acknowledgements](#acknowledgements)
- [License](#license)

---

## 🚀 Features

- 📡 **Real-time network monitoring** using Zeek
- 🧠 **Anomaly detection** with IsolationForest (trained on CIC-IDS 2018)
- 🛡️ **Signature-based detection** for rule-based threats like port scans
- 📊 **Flow-level feature extraction** (e.g., byte rates, packet rates, flags)
- ⚠️ **Threat detection console output** with structured threat data

---

## 🧰 Tech Stack

- **Python 3.10**
- **Zeek** – Real-time network traffic analyzer
- **scikit-learn** – IsolationForest for anomaly detection
- **joblib** – For loading pre-trained ML models
- **WSL** (for Windows) – Zeek runs in Ubuntu via WSL
- **Matplotlib / Pandas / NumPy** (used during training, optional for runtime)

---

## ⚙️ Installation

### 1. Clone the repository
```bash
git clone https://github.com/otuemre/RealTimeNIDS.git
cd RealTimeNIDS
```

### 2. Install Python dependencies
```bash
pip install -r requirements.txt
```

### 3. Install Zeek

For Ubuntu (WSL or native):
```bash
sudo apt update
sudo apt install zeek
```

---

## 🔧 Zeek Configuration

To start Zeek and monitor your interface:
```bash
sudo /opt/zeek/bin/zeek -i eth0 -C
```

- `eth0` is your interface (check with `ifconfig` inside WSL)
- `-C` disables checksum validation (useful in WSL)

> 📁 Zeek will generate a `conn.log` file containing flow records.

---

## ▶️ Running the System

Change the path to `conn.log` in `src/realtime_nids/zeek_monitor.py`:
```python
LOG_FILE = 'PATH_TO_YOUR_CONN_FILE'
```

Start your monitor in another terminal:

```bash
python src/realtime_nids/zeek_monitor.py
```

You’ll see real-time detection logs like:
```
[*] Starting real-time Zeek log monitor...
[!] 0 Live Threat Detect:
    → {'type': 'signature', 'rule': 'port_scan', 'confidence': 1.0}
    → {'type': 'anomaly', 'score': -0.72, 'confidence': 0.72}
```

> ✅ Works for live tests (e.g., `hping3`, simulated attacks).

---

## 📁 Project Structure

| File                                    | Description                                                               |
|-----------------------------------------|---------------------------------------------------------------------------|
| `src/realtime_nids/zeek_monitor.py`     | Reads and parses Zeek `conn.log` for real-time flow monitoring            |
| `src/realtime_nids/detection_engine.py` | Contains both signature-based and IsolationForest-based anomaly detection |
| `model/isolation_model.pkl`             | Pre-trained IsolationForest model (from CIC-IDS 2018)                     |
| `src/realtime_nids/zeek_parser.py`      | (Optional helper) Parses logs and maps fields cleanly                     |
| `notebooks/`                            | Jupyter notebooks for model training and threshold tuning                 |
| `datasets/`                             | Location for downloaded training datasets                                 |
| `.env`                                  | Configuration (optional, not required)                                    |

---

## 📈 Future Improvements

- Add support for **model retraining pipeline**
- Dynamic threshold tuning via **quantile calibration**
- Web dashboard for real-time alert visualization
- Support for other models (e.g., One-Class SVM, Autoencoders)
- Add more signature-based approach derived on **CIC-IDS 2018** dataset

---

## 🙏 Acknowledgements

- Based on FreeCodeCamp's [Real-Time IDS Tutorial](https://www.freecodecamp.org/news/build-a-real-time-intrusion-detection-system-with-python/)
- IDS 2018 Intrusion CSVs (CSE-CIC-IDS2018) – Source: [Kaggle: IDS Intrusion CSVs](https://www.kaggle.com/datasets/solarmainframe/ids-intrusion-csv/)

---

## 📝 License

Licensed under the [MIT License](LICENSE.md). You’re free to use and modify responsibly.
