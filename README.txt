NIDS + WEBSITE SECURITY CHECKER — COMPLETE PROJECT
==================================================

FEATURES
--------
1. Flask dashboard with live NIDS statistics and recent alert history.
2. Website Security Checker:
   - Accepts URLs with or without http:// or https://.
   - Validates URL format and hostname.
   - Performs DNS resolution and displays resolved IP addresses.
   - Checks connection/HTTP response and reports HTTP status.
   - Validates HTTPS certificates using Python requests / the OS trust store.
   - Shows redirects and their destination without automatically following them.
   - Displays useful DNS, timeout, TLS and connection error details.
   - Exports the most recent check as JSON or CSV.
3. Offline PCAP/PCAPNG analyzer for Wireshark captures.
4. Live capture script using Scapy.
5. Basic detection smoke tests.

IMPORTANT LIMITATION
--------------------
This is an educational technical checker and rule-based NIDS prototype, not a
commercial malware/phishing reputation service. It does not prove that a site
is safe or malicious. DNS failures can be caused by typos, DNS/network problems,
or a nonexistent domain. HTTP 200 means a server responded, not that its content
is trustworthy. The website checker blocks local/private/reserved IP destinations
as a safety measure. No traffic blocking is performed.

REQUIREMENTS
------------
Windows 10/11, Python 3.10+ (tested by the project owner on Python 3.14), and
an internet connection for pip installation and website checks.

INSTALL
-------
1. Extract the ZIP file.
2. Open Command Prompt in the inner NIDS_Complete_Project folder (the folder
   that contains requirements.txt and dashboard.py).
3. Run:
       python -m pip install -r requirements.txt

RUN DASHBOARD
-------------
Run either:
       python dashboard.py
or double-click run_dashboard.bat.
Open this address in your browser:
       http://127.0.0.1:5000
Keep the terminal open while using the dashboard. Press Ctrl+C to stop it.

WEBSITE CHECKER TESTS
---------------------
Try these in the Website Security Checker:
  https://example.org                   Expected: normally HTTP 200
  https://google.com                    Expected: may show an HTTP redirect
  https://this-domain-should-not-exist-12345.com
                                         Expected: normally DNS resolution error

After a check, click Download JSON Report or Download CSV Report. The report
contains the timestamp, submitted URL, hostname, protocol, port, DNS status,
resolved IPs, connection status, HTTP status, TLS status, assessment and errors.
Network and DNS results may vary by machine and time.

RUN LIVE NIDS
-------------
Run run_nids.bat or:
       python test_capture.py
Choose the appropriate network interface if the script prompts for it. Packet
capture may require administrator privileges and a compatible Npcap installation.
Stop capture with Ctrl+C. Only monitor networks and devices you are authorized to
inspect. The exact live detection behavior depends on the rules in the script.

ANALYZE WIRESHARK CAPTURE
-------------------------
1. In Wireshark, save a capture as .pcap or .pcapng.
2. Copy the capture into this project folder, or provide its full path.
3. Run:
       python pcap_analyzer.py your_capture.pcapng
4. The analyzer writes pcap_alerts.csv and pcap_summary.json in the project folder.
5. Refresh the dashboard to see the summary.

TESTS
-----
Run:
       python test_detection.py

TROUBLESHOOTING
---------------
- 'requirements.txt not found': cd into the folder that actually contains it.
- Flask/Scapy import error: run python -m pip install -r requirements.txt using
  the same Python interpreter you use to start the project.
- Website checker cannot resolve a hostname: verify the spelling and your DNS/
  network connection. This is not, by itself, evidence of maliciousness.
- HTTPS certificate failure: check system date/time and certificate trust settings.
- Live capture shows no packets: verify interface selection, permissions and Npcap.
- Port 5000 is busy: stop the other dashboard instance before starting another.

FILES
-----
dashboard.py         Main Flask dashboard and website checker
test_capture.py      Scapy live capture and rule-based monitoring
pcap_analyzer.py      Offline PCAP/PCAPNG analyzer
test_detection.py     Detection smoke tests
requirements.txt      Python package dependencies
run_dashboard.bat     Starts dashboard.py
run_nids.bat          Starts live monitoring
analyze_capture.bat   Helper for offline capture analysis
alerts.csv            Live alert history (sample/working data)
stats.txt             Live statistics (sample/working data)
pcap_alerts.csv       Offline alert output (sample/working data)
pcap_summary.json     Offline summary (sample/working data)
