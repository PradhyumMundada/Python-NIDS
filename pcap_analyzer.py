"""Offline analyzer for Wireshark PCAP/PCAPNG files."""
import argparse, csv, json
from datetime import datetime
from pathlib import Path
from collections import defaultdict
from scapy.all import PcapReader, IP, IPv6, TCP, UDP, DNS, DNSQR
BASE=Path(__file__).resolve().parent

def analyze(path):
    path=Path(path).expanduser().resolve()
    if not path.is_file(): raise FileNotFoundError(f'Capture file not found: {path}')
    total=ipv4=ipv6=tcp=udp=dns_queries=0
    port_tracker=defaultdict(set); alerts=[]
    with PcapReader(str(path)) as reader:
        for pkt in reader:
            total+=1
            if IP in pkt: ipv4+=1; src,dst=pkt[IP].src,pkt[IP].dst
            elif IPv6 in pkt: ipv6+=1; src,dst=pkt[IPv6].src,pkt[IPv6].dst
            else: continue
            if TCP in pkt:
                tcp+=1; port_tracker[src].add(pkt[TCP].dport)
            if UDP in pkt: udp+=1
            if DNS in pkt and pkt[DNS].qr==0 and pkt[DNS].qd:
                try:
                    if pkt[DNS].qd.qname: dns_queries+=1
                except Exception: pass
    for src,ports in port_tracker.items():
        if len(ports)>=10: alerts.append([datetime.now().strftime('%Y-%m-%d %H:%M:%S'),src,'Possible Port Scan','HIGH',f'{len(ports)} distinct TCP destination ports in capture'])
    summary={'capture_file':path.name,'analysis_time':datetime.now().strftime('%Y-%m-%d %H:%M:%S'),'total_packets':total,'ipv4_packets':ipv4,'ipv6_packets':ipv6,'tcp_packets':tcp,'udp_packets':udp,'dns_query_names':dns_queries,'possible_port_scan_alerts':len(alerts)}
    with (BASE/'pcap_alerts.csv').open('w',newline='',encoding='utf-8') as f:
        w=csv.writer(f); w.writerow(['Time','Source IP','Alert Type','Severity','Details']); w.writerows(alerts)
    (BASE/'pcap_summary.json').write_text(json.dumps(summary,indent=2),encoding='utf-8')
    print(json.dumps(summary,indent=2)); print(f'Offline alerts saved to: {BASE/"pcap_alerts.csv"}'); print(f'Summary saved to: {BASE/"pcap_summary.json"}')
    return summary
if __name__=='__main__':
    parser=argparse.ArgumentParser(description='Analyze a saved Wireshark PCAP/PCAPNG file')
    parser.add_argument('capture_file',help='Path to .pcap or .pcapng file')
    args=parser.parse_args()
    try: analyze(args.capture_file)
    except Exception as e: raise SystemExit(str(e))
