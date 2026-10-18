
from pathlib import Path
import shutil
import json

base = Path(__file__).resolve().parent
dashboard = base / "dashboard.py"

if not dashboard.exists():
    raise SystemExit("ERROR: dashboard.py not found in this folder.")

source = dashboard.read_text(encoding="utf-8")
updated = source

replacements = [
    ('<div class="num">{{stats.total}}</div>',
     '<div class="num" id="stat-total">{{stats.total}}</div>'),
    ('<div class="num">{{stats.normal}}</div>',
     '<div class="num" id="stat-normal">{{stats.normal}}</div>'),
    ('<div class="num">{{stats.suspicious}}</div>',
     '<div class="num" id="stat-suspicious">{{stats.suspicious}}</div>'),
    ('<div class="num">{{alert_count}}</div>',
     '<div class="num" id="stat-alert-count">{{alert_count}}</div>'),
]

for old, new in replacements:
    if updated.count(old) != 1:
        raise SystemExit(
            f"Expected one occurrence of {old!r}; "
            "no changes were made."
        )
    updated = updated.replace(old, new, 1)

closing = "</main></body></html>'''"

script = """</main>
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
</script></body></html>'''"""

if updated.count(closing) != 1:
    raise SystemExit("Dashboard HTML ending not found; no changes were made.")

updated = updated.replace(closing, script, 1)

anchor = "\nif __name__=='__main__':"

route = '''

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

'''

if updated.count(anchor) != 1:
    raise SystemExit("Flask startup section not found; no changes were made.")

updated = updated.replace(anchor, route + anchor, 1)

backup = base / "dashboard.py.before_auto_refresh.bak"

if backup.exists():
    raise SystemExit(
        "Backup already exists. Stop and check before retrying."
    )

shutil.copy2(dashboard, backup)
dashboard.write_text(updated, encoding="utf-8")

print("SUCCESS: Automatic statistics refresh enabled.")
print("Backup:", backup)
print("Refresh interval: 2 seconds")
