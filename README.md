# 🔐 AI-Powered Network Intrusion Detection System (NIDS)

## 📌 Overview

This project implements a **Machine Learning-based Network Intrusion Detection System (NIDS)** designed to monitor network traffic in real time and detect potential cyber attacks.

The system captures network packets, extracts meaningful features, and applies a trained machine learning model to classify traffic as **normal or malicious**. When suspicious activity is detected, alerts are generated and logged for further analysis.

---

## 🎯 Objectives

* Detect network intrusions automatically
* Monitor traffic in real time
* Reduce false positives using Machine Learning
* Provide alerts for suspicious activities
* Build a scalable and modular security system

---

## ⚙️ System Architecture

The system follows a **modular pipeline architecture**, where each component has a specific role:

### 🧩 1. Packet Processing Layer (`src/packet_processor.py`)

* Captures network packets using Scapy
* Filters relevant protocols (TCP, UDP, ICMP)
* Preprocesses raw data

---

### 🧩 2. Feature Extraction Layer (`src/feature_extractor.py`)

* Converts raw packets into structured features
* Extracted features include:

  * Packet size
  * Source and destination IP
  * Ports
  * TCP flags
  * Connection frequency

---

### 🧩 3. Machine Learning Model (`src/ml_model.py`)

* Uses Scikit-learn for classification
* Trained to distinguish between normal and malicious traffic
* Outputs:

  * `0` → Normal traffic
  * `1` → Attack detected

---

### 🧩 4. NIDS Engine (`src/nids_engine.py`)

* Core component of the system
* Orchestrates the entire detection pipeline
* Connects packet processing, feature extraction, and ML prediction

---

### 🧩 5. Alert System (`src/alert_system.py`)

* Handles detection results
* Generates alerts for suspicious activity
* Logs potential threats

---

### 🧩 6. Logging System (`src/logger.py`)

* Records system activity and detected attacks
* Stores logs for monitoring and analysis

---

### 🧩 7. Backend API (`app.py`)

* Built with Flask
* Provides REST API endpoints
* Connects backend logic with frontend dashboard

---

### 🧩 8. Frontend Dashboard (`web/`)

* Displays alerts and system activity
* Provides real-time monitoring interface
* Built using HTML, CSS, and JavaScript

---

## 🔄 Workflow

1. Capture network packets
2. Preprocess and clean data
3. Extract relevant features
4. Send features to ML model
5. Classify traffic (normal / attack)
6. Generate alerts if needed
7. Log results and display on dashboard

---

## 🛠️ Technologies Used

* Python
* Scikit-learn
* Flask
* Scapy
* HTML / CSS / JavaScript

---

## ▶️ Installation

```bash
git clone https://github.com/khayrataya42-commits/nids-ml-detection-system.git
cd nids-ml-detection-system
pip install -r requirements.txt
```

---

## 💻 Usage

### Run Detection Mode

```bash
python main.py --mode detection
```

### Run API Server

```bash
python main.py --mode api
```

Then open:

```
http://localhost:5000
```

---

## 📁 Project Structure

```
nids-ml-detection-system/
│
├── src/                # Core logic (ML, processing, engine)
├── web/                # Frontend dashboard
├── config/             # Configuration files
├── logs/               # System logs
├── docs/               # Documentation
├── app.py              # Flask backend
├── main.py             # Entry point
├── requirements.txt    # Dependencies
└── README.md
```

---

## 🧠 Key Features

* Real-time network monitoring
* Machine Learning-based detection
* Modular architecture
* Alert generation system
* Web-based visualization

---

## ⚠️ Limitations

* Depends on training data quality
* Possible false positives
* Requires continuous improvement

---

## 🚀 Future Improvements

* Integrate Deep Learning models
* Add automatic IP blocking
* Deploy on cloud environments
* Improve dashboard visualization
* Enhance detection accuracy

---

## ⚠️ Disclaimer

This project is intended for **educational and research purposes only**. Do not use it in unauthorized environments.

---

## 👩‍💻 Author

Developed as part of a cybersecurity and network analysis project.

---
