

\# Network Intrusion Detection System (NIDS)



\## Overview

A Python-based Network Intrusion Detection System prototype that monitors network packets, detects selected suspicious traffic patterns, and displays monitoring statistics through a Flask dashboard.



\## Features

\- Live packet capture using Scapy

\- Rule-based possible port-scan detection

\- High-traffic warnings

\- Live monitoring dashboard with automatic statistics refresh

\- Website technical checks for DNS, connectivity, HTTP responses, and HTTPS certificates

\- Offline analysis of saved PCAP/PCAPNG captures

\- CSV and JSON reporting



\## Technologies Used

\- Python

\- Scapy

\- Flask

\- HTML and CSS

\- JavaScript

\- Wireshark-compatible PCAP/PCAPNG files



\## Project Structure

\- `dashboard.py` — Flask dashboard and website checker

\- `test\_capture.py` — Live packet capture and detection

\- `test\_detection.py` — Automated detection tests

\- `pcap\_analyzer.py` — Offline packet-capture analysis

\- `requirements.txt` — Python dependencies

\- `run\_dashboard.bat` — Dashboard launcher

\- `run\_nids.bat` — Monitoring launcher



\## Setup

1\. Install Python.

2\. Install the dependencies:

&#x20;  `pip install -r requirements.txt`

3\. Start the dashboard using `python dashboard.py`.

4\. Start packet monitoring using `run\_nids.bat` in a separate terminal.



Live packet capture may require administrator privileges or suitable packet-capture drivers, depending on the Windows setup.



\## Limitations

This is an educational, rule-based prototype. A high-traffic warning or port-scan indicator is not proof of a cyberattack. Website reachability and certificate checks do not establish whether a website is malicious.



\## Responsible Use

Only capture and analyze network traffic you are authorized to monitor. Avoid publishing packet captures or logs that contain private information.



