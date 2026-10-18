"""Flask dashboard for live NIDS stats, offline analysis, and website validation."""
from flask import Flask, request, render_template_string, session, send_file
from pathlib import Path
from datetime import datetime
from urllib.parse import urlparse
import csv, ipaddress, json, socket, io, secrets
import requests

BASE=Path(__file__).resolve().parent
app=Flask(__name__)
app.secret_key=secrets.token_hex(32)
app.config['MAX_CONTENT_LENGTH']=16*1024

PAGE=r'''<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>NIDS Security Dashboard</title><style>
:root{--bg:#f3f6fb;--card:#fff;--ink:#182230;--muted:#637083;--blue:#2359d6;--line:#e2e8f0}*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--ink);font-family:Inter,Segoe UI,Arial,sans-serif}.wrap{max-width:1300px;margin:auto;padding:28px}.hero{padding:24px 0 28px}.hero h1{font-size:clamp(28px,4vw,40px);margin:0 0 8px}.hero p{color:var(--muted);margin:0}.section{margin:24px 0}.section h2{font-size:23px;margin:0 0 14px}.grid{display:grid;grid-template-columns:repeat(4,minmax(0,1fr));gap:14px}.card,.panel{background:var(--card);border:1px solid var(--line);border-radius:16px;padding:22px;box-shadow:0 5px 18px #16213b0a}.metric{text-align:center}.metric .label{color:var(--muted);font-weight:600}.metric .num{font-size:34px;font-weight:750;margin-top:10px}.hint{color:var(--muted);font-size:13px;margin-top:12px;line-height:1.5}.panel{margin-bottom:14px}.split{display:grid;grid-template-columns:1fr 1fr;gap:14px}.formrow{display:flex;gap:10px;margin-top:14px}.formrow input{flex:1;min-width:0;border:1px solid #cbd5e1;border-radius:10px;padding:13px;font-size:15px}.btn{border:0;border-radius:10px;background:var(--blue);color:white;padding:13px 17px;font-weight:700;cursor:pointer}.btn:hover{filter:brightness(.94)}.status{padding:12px 14px;border-radius:10px;margin:14px 0;font-weight:700}.good{background:#e8f8ee;color:#17643a}.warn{background:#fff5df;color:#8b5700}.bad{background:#ffebeb;color:#9e2525}.details{display:grid;grid-template-columns:170px 1fr;gap:9px 12px;font-size:14px}.details .key{color:var(--muted)}.details div{overflow-wrap:anywhere}table{width:100%;border-collapse:collapse;font-size:13px}th{background:#263342;color:#fff;text-align:left;padding:12px}td{padding:12px;border-bottom:1px solid var(--line);vertical-align:top;overflow-wrap:anywhere}tr:last-child td{border-bottom:0}.tablewrap{overflow:auto}.tag{display:inline-block;background:#e9efff;color:#254bb4;border-radius:30px;padding:4px 9px;font-size:12px;font-weight:700}.footer{color:var(--muted);font-size:12px;padding:20px 0}@media(max-width:900px){.grid{grid-template-columns:repeat(2,minmax(0,1fr))}.split{grid-template-columns:1fr}}@media(max-width:540px){.wrap{padding:16px}.grid{grid-template-columns:1fr 1fr}.card{padding:15px}.formrow{flex-direction:column}.details{grid-template-columns:1fr;gap:4px}.details .key{margin-top:8px}}
</style></head><body><main class="wrap"><header class="hero"><h1>Network Intrusion Detection System</h1><p>Live network monitoring · Wireshark offline analysis · Website validation</p></header>
<section class="section"><h2>Live Monitoring Statistics</h2><div class="grid"><div class="card metric"><div class="label">Packets Monitored</div><div class="num" id="stat-total">{{stats.total}}</div></div><div class="card metric"><div class="label">Normal Traffic</div><div class="num" id="stat-normal">{{stats.normal}}</div></div><div class="card metric"><div class="label">Suspicious Packets</div><div class="num" id="stat-suspicious">{{stats.suspicious}}</div></div><div class="card metric"><div class="label">Recorded Live Alerts</div><div class="num" id="stat-alert-count">{{alert_count}}</div></div></div><p class="hint">Stats are read from stats.txt; live alert history is read from alerts.csv. A high-traffic warning is not proof of an attack. Packets that do not trigger configured rules are not guaranteed safe.</p></section>
<section class="section"><h2>Website Security Checker</h2><div class="panel"><p>Enter a website to check URL format, DNS resolution, connection reachability, HTTP response and HTTPS certificate validation. This is a basic technical check, not a malware reputation verdict.</p><form method="post" action="/check"><div class="formrow"><input name="url" placeholder="https://example.com" value="{{submitted_url}}" required maxlength="2048"><button class="btn" type="submit">Check Website</button></div></form>{% if result %}<div class="status {{result.css}}">{{result.title}}</div><div class="details"><div class="key">Submitted URL</div><div>{{result.url}}</div><div class="key">Hostname</div><div>{{result.hostname or 'Unavailable'}}</div><div class="key">DNS status</div><div>{{result.dns_status}}</div><div class="key">Resolved IP addresses</div><div>{{result.ips|join(', ') if result.ips else 'None returned'}}</div><div class="key">Connection status</div><div>{{result.connection}}</div><div class="key">HTTP status</div><div>{{result.http_status or 'Not available'}}</div><div class="key">HTTPS certificate</div><div>{{result.tls_status}}</div><div class="key">Assessment</div><div>{{result.assessment}}</div>{% if result.scheme %}<div class="key">Protocol</div><div>{{result.scheme|upper}}</div><div class="key">Port</div><div>{{result.port}}</div>{% endif %}{% if result.redirect %}<div class="key">Redirect destination</div><div>{{result.redirect}}</div>{% endif %}{% if result.error %}<div class="key">Details / error</div><div>{{result.error}}</div>{% endif %}</div><p class="hint">{{result.assessment}}</p><p><a class="btn" href="/report.json">Download JSON Report</a> <a class="btn" href="/report.csv">Download CSV Report</a></p>{% endif %}<p class="hint">Safety: the checker refuses private, loopback, link-local and reserved destination addresses to reduce SSRF risk. A failed connection may be caused by DNS, firewall, server or network issues; it does not prove a site is malicious.</p></div></section>
<section class="section"><h2>Wireshark Offline Analysis</h2><p class="hint">Run <code>python pcap_analyzer.py your_capture.pcapng</code> on a saved Wireshark capture to refresh this section.</p><div class="panel">{% if pcap %}<div class="details">{% for k,v in pcap.items() %}<div class="key">{{k.replace('_',' ').title()}}</div><div>{{v}}</div>{% endfor %}</div>{% else %}No capture analyzed yet. Run pcap_analyzer.py with a saved .pcap or .pcapng file.{% endif %}</div></section>
<section class="section"><h2>Live Security Alerts <span class="tag">latest 100</span></h2><div class="panel tablewrap">{% if alerts %}<table><thead><tr><th>Time</th><th>Source IP</th><th>Alert Type</th><th>Severity</th><th>Details</th></tr></thead><tbody>{% for a in alerts %}<tr>{% for c in a %}<td>{{c}}</td>{% endfor %}</tr>{% endfor %}</tbody></table>{% else %}No live alerts recorded yet.{% endif %}</div></section>
<div class="footer">Educational NIDS prototype · Rule-based indicators only · No traffic blocking is performed.</div></main>
<script>
async function refreshNidsStats() {
  try {
    const response = await fetch('/api/stats', {cache: 'no-store'});
    if (!response.ok) return;
    const data = await response.json();
    document.getElementById('stat-total').textContent = data.stats.total;
    document.getElementById('stat-normal').textContent = data.stats.normal;
    document.getElementById('stat-suspicious').textContent = data.stats.suspicious;
    document.getElementById('stat-alert-count').textContent = data.alert_count;
  } catch (error) {
    console.warn('Statistics refresh failed:', error);
  }
}
refreshNidsStats();
setInterval(refreshNidsStats, 2000);
</script></body></html>'''

def read_stats():
    try:
        vals=(BASE/'stats.txt').read_text(encoding='utf-8').splitlines()
        nums=[int(v) for v in vals[:3]]
        while len(nums)<3: nums.append(0)
        return {'total':nums[0],'normal':nums[1],'suspicious':nums[2]}
    except (OSError,ValueError): return {'total':0,'normal':0,'suspicious':0}

def read_csv(name, limit=None):
    p=BASE/name
    try:
        with p.open(newline='',encoding='utf-8-sig') as f:
            rows=list(csv.reader(f))
        return rows[1:][-limit:] if limit else rows[1:]
    except (OSError,csv.Error): return []

def load_pcap_summary():
    try:
        data=json.loads((BASE/'pcap_summary.json').read_text(encoding='utf-8'))
        return {k:v for k,v in data.items()}
    except (OSError,ValueError): return None

def check_website(raw):
    result={'checked_at':datetime.now().astimezone().isoformat(timespec='seconds'),'url':raw,'hostname':'','scheme':'','port':None,'dns_status':'Not checked','ips':[],'connection':'Not checked','http_status':None,'tls_status':'Not applicable','redirect':'','assessment':'Not determined','error':'','css':'warn','title':'Website check incomplete'}
    value=raw.strip()
    if not value: result.update(title='Enter a website URL',css='bad',error='The URL field is empty.'); return result
    if len(value)>2048: result.update(title='Invalid URL',css='bad',error='URL is too long.'); return result
    if '://' not in value: value='https://'+value
    try:
        parsed=urlparse(value)
        if parsed.scheme not in ('http','https') or not parsed.hostname or parsed.username or parsed.password:
            raise ValueError('Enter a valid HTTP or HTTPS URL without embedded credentials.')
        hostname=parsed.hostname.encode('idna').decode('ascii').lower()
        if hostname in ('localhost',) or hostname.endswith('.localhost'):
            raise ValueError('Localhost destinations are not allowed by this checker.')
        port=parsed.port or (443 if parsed.scheme=='https' else 80)
    except (ValueError,UnicodeError) as e:
        result.update(title='Invalid website URL',css='bad',error=str(e),assessment='URL format could not be validated.'); return result
    result['url']=value; result['hostname']=hostname; result['scheme']=parsed.scheme; result['port']=port
    try:
        infos=socket.getaddrinfo(hostname,port,type=socket.SOCK_STREAM)
        ips=sorted({info[4][0].split('%')[0] for info in infos})
        result['ips']=ips; result['dns_status']='Resolved'
    except socket.gaierror as e:
        result.update(title='Website hostname could not be resolved',css='bad',dns_status='Failed',connection='Not attempted',assessment='Hostname is not resolvable from this machine.',error=str(e)); return result
    for ip in ips:
        try:
            parsed_ip=ipaddress.ip_address(ip)
            if not parsed_ip.is_global:
                result.update(title='Destination blocked by safety policy',css='warn',connection='Not attempted',assessment='Private, local, link-local or reserved IPs are not checked.',error=f'Resolved address {ip} is not a globally routable address.'); return result
        except ValueError: pass
    try:
        response=requests.get(value,timeout=(4,7),allow_redirects=False,stream=True,headers={'User-Agent':'Educational-NIDS-Website-Checker/1.0'})
        result['http_status']=response.status_code
        result['connection']='HTTP response received'
        if parsed.scheme=='https': result['tls_status']='Certificate validated by requests/OS trust store'
        result['assessment']='Reachability checked only; maliciousness not assessed.'
        if 300<=response.status_code<400:
            loc=response.headers.get('Location','')
            result['redirect']=loc or 'Not supplied by server'
            result['title']='Website responded with a redirect'; result['css']='warn'; result['error']=f'Redirect response ({response.status_code}); target not followed automatically.'
        elif response.status_code>=400:
            result['title']='Website responded with an HTTP error'; result['css']='warn'; result['error']=f'Server returned HTTP {response.status_code}; this does not necessarily mean the domain is unknown or malicious.'
        else:
            result['title']='Website is reachable'; result['css']='good'
        response.close()
    except requests.exceptions.SSLError as e:
        result.update(title='HTTPS certificate validation failed',css='bad',connection='TLS/HTTPS check failed',tls_status='Validation failed',assessment='Certificate validation error; investigate before trusting the site.',error=str(e)[:500])
    except requests.exceptions.Timeout as e:
        result.update(title='Website connection timed out',css='warn',connection='Timed out',assessment='Unreachable within the configured timeout; not proof of maliciousness.',error=str(e) or 'Connection timed out.')
    except requests.RequestException as e:
        result.update(title='Website could not be reached',css='warn',connection='Failed',assessment='Connection failure; not proof of maliciousness.',error=str(e)[:500])
    return result

@app.route('/',methods=['GET'])
def index():
    alerts=read_csv('alerts.csv',100)
    return render_template_string(PAGE,stats=read_stats(),alert_count=len(read_csv('alerts.csv')),alerts=alerts,pcap=load_pcap_summary(),result=None,submitted_url='')

@app.route('/check',methods=['POST'])
def check():
    raw=request.form.get('url','')
    result=check_website(raw)
    session['last_website_report'] = result
    return render_template_string(PAGE,stats=read_stats(),alert_count=len(read_csv('alerts.csv')),alerts=read_csv('alerts.csv',100),pcap=load_pcap_summary(),result=result,submitted_url=raw)


@app.route('/api/stats', methods=['GET'])
def api_stats():
    payload = {
        'stats': read_stats(),
        'alert_count': len(read_csv('alerts.csv'))
    }
    return app.response_class(
        json.dumps(payload),
        mimetype='application/json',
        headers={'Cache-Control': 'no-store'}
    )


if __name__=='__main__':
    print('NIDS dashboard: http://127.0.0.1:5000')
    app.run(host='127.0.0.1',port=5000,debug=False)


@app.route('/report.json')
def download_json_report():
    report = session.get('last_website_report')
    if not report:
        return 'No website report yet. Return to the dashboard and check a website first.', 404
    payload = json.dumps(report, indent=2, ensure_ascii=False)
    return app.response_class(payload, mimetype='application/json', headers={'Content-Disposition': 'attachment; filename=website_security_report.json'})

@app.route('/report.csv')
def download_csv_report():
    report = session.get('last_website_report')
    if not report:
        return 'No website report yet. Return to the dashboard and check a website first.', 404
    output = io.StringIO(newline='')
    writer = csv.writer(output)
    writer.writerow(['Field', 'Value'])
    for key, value in report.items():
        if isinstance(value, list):
            value = ', '.join(str(x) for x in value)
        writer.writerow([key, value])
    return app.response_class(output.getvalue(), mimetype='text/csv; charset=utf-8', headers={'Content-Disposition': 'attachment; filename=website_security_report.csv'})
