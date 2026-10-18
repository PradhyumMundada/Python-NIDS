"""Live packet monitoring for the educational NIDS project."""
from collections import defaultdict, deque
from datetime import datetime
from pathlib import Path
import csv, ipaddress, json, os, socket, time
from scapy.all import sniff, IP, IPv6, TCP, UDP, DNS, DNSQR, DNSRR, get_if_addr

BASE = Path(__file__).resolve().parent
ALERTS = BASE / 'alerts.csv'
STATS = BASE / 'stats.txt'
STATE = BASE / 'live_state.json'
INTERFACE = os.getenv('NIDS_INTERFACE', 'Wi-Fi')
WINDOW_SECONDS = 10
HIGH_TRAFFIC_THRESHOLD = 100
PORT_SCAN_THRESHOLD = 10
HEADER = ['Time','Source IP','Alert Type','Severity','Details']
counts = defaultdict(int)
ports = defaultdict(set)
packet_times = defaultdict(deque)
ip_to_domain = {}
metrics = {'total':0,'normal':0,'suspicious':0}

def ensure_files():
    if not ALERTS.exists() or ALERTS.stat().st_size == 0:
        with ALERTS.open('w', newline='', encoding='utf-8') as f: csv.writer(f).writerow(HEADER)

def save_alert(src, kind, severity, details):
    ensure_files()
    with ALERTS.open('a', newline='', encoding='utf-8') as f:
        csv.writer(f).writerow([datetime.now().strftime('%Y-%m-%d %H:%M:%S'),src,kind,severity,details])
    print(f'[{severity}] {kind}: {src} — {details}')

def write_stats():
    STATS.write_text(f"{metrics['total']}\n{metrics['normal']}\n{metrics['suspicious']}\n", encoding='utf-8')
    STATE.write_text(json.dumps({'interface':INTERFACE,'updated':datetime.now().isoformat(timespec='seconds'),'metrics':metrics}, indent=2), encoding='utf-8')

def packet_pair(pkt):
    if IP in pkt: return pkt[IP].src, pkt[IP].dst
    if IPv6 in pkt: return pkt[IPv6].src, pkt[IPv6].dst
    return None, None

def process_dns(pkt):
    if DNS not in pkt or pkt[DNS].qd is None: return
    dns = pkt[DNS]
    try:
        qname = dns.qd.qname.decode(errors='ignore').rstrip('.')
        if qname and dns.qr == 0: print(f'[DNS QUERY] {qname}')
    except Exception: pass
    if dns.qr == 1 and dns.an:
        for answer in dns.an:
            try:
                name = answer.rrname.decode(errors='ignore').rstrip('.')
                if answer.type in (1, 28) and name:
                    ip_to_domain[str(answer.rdata)] = name
            except Exception: continue

def handle(pkt):
    src,dst = packet_pair(pkt)
    if not src: return
    metrics['total'] += 1
    now = time.time()
    remote = dst
    try:
        if ipaddress.ip_address(src).is_private or ipaddress.ip_address(src).is_loopback:
            remote = dst
        else: remote = src
    except ValueError: pass
    process_dns(pkt)
    proto = 'TCP' if TCP in pkt else ('UDP' if UDP in pkt else 'Other')
    sport = pkt[TCP].sport if TCP in pkt else (pkt[UDP].sport if UDP in pkt else '-')
    dport = pkt[TCP].dport if TCP in pkt else (pkt[UDP].dport if UDP in pkt else '-')
    print(f'{src:>39} -> {dst:<39} {proto:<5} {sport!s:>5} -> {dport!s:<5} {len(pkt)} bytes  {ip_to_domain.get(remote,"Unknown")}')
    metrics['normal'] += 1
    packet_times[src].append(now)
    while packet_times[src] and now-packet_times[src][0] > WINDOW_SECONDS: packet_times[src].popleft()
    if TCP in pkt and isinstance(dport, int):
        ports[src].add(dport)
        if len(ports[src]) >= PORT_SCAN_THRESHOLD and len(ports[src]) == PORT_SCAN_THRESHOLD:
            metrics['suspicious'] += 1
            save_alert(src,'Possible Port Scan','HIGH',f'{len(ports[src])} distinct destination ports observed; destination {dst}')
    if len(packet_times[src]) == HIGH_TRAFFIC_THRESHOLD:
        save_alert(src,'High Traffic Warning','MEDIUM',f'{len(packet_times[src])} packets in about {WINDOW_SECONDS} seconds; volume alone does not confirm an attack. Destination IP: {dst}')
    if metrics['total'] % 25 == 0: write_stats()

def main():
    ensure_files(); write_stats()
    print('='*65); print('NETWORK INTRUSION DETECTION SYSTEM — LIVE CAPTURE'); print(f'Interface: {INTERFACE}'); print('Press Ctrl+C to stop.'); print('='*65)
    try:
        sniff(iface=INTERFACE, prn=handle, store=False, stop_filter=lambda _: False)
    except KeyboardInterrupt: pass
    except Exception as e:
        print(f'Capture error: {e}')
        print('Check Npcap installation, interface name and administrator permissions.')
    finally: write_stats(); print(f"Total IP packets captured: {metrics['total']}\nNIDS stopped.")
if __name__ == '__main__': main()
