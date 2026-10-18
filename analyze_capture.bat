@echo off
cd /d "%~dp0"
if "%~1"=="" (
  echo Usage: analyze_capture.bat filename.pcapng
  echo Example: analyze_capture.bat dns_test.pcapng
  pause
  exit /b 1
)
python pcap_analyzer.py "%~1"
pause
