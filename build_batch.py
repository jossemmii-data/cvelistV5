import json, os
from datetime import datetime

# Build date
# Input date example -> "2026-05-13T14:30:00.000Z"
# Output date (same than input, but usable) -> "2026-05-13T14:30:00.000Z+00:00"
def parse_iso(s):
    return datetime.fromisoformat(s.replace('Z', '+00:00'))

# Write in the output of the step
def set_output(key, value):
    with open(os.environ['GITHUB_OUTPUT'], 'a') as f:
        f.write(f"{key}={value}\n")

# Max Date
cutoff = parse_iso("${{ steps.max.outputs.max }}")

# Open deltaLog.json
with open('cves/deltaLog.json') as f:
    delta = json.load(f)

# Sort deltaLog.json. Each block is sorted using fetchTime. New < Old
delta_sorted = sorted(delta, key=lambda b: parse_iso(b['fetchTime']))

latest = {}  # cve_id -> (action, githubLink)                                             # latest = {(action, githubLink)}
for block in delta_sorted:                                                                # in each block...
    for kind, action in (('new', 'NEW'), ('updated', 'UPDATED')):                         
        for cve in block.get(kind, []):
            if parse_iso(cve['dateUpdated']) <= cutoff:
                continue
            if action == 'UPDATED' and latest.get(cve['cveId'], (None,))[0] == 'NEW':
                action = 'NEW'
            latest[cve['cveId']] = (action, cve['githubLink'])

if not latest:
    print("No hay cambios nuevos")
    set_output('has_changes', 'false')
    raise SystemExit(0)

# Total of CVES
print(f"CVEs to process: {len(latest)}")
os.makedirs('/tmp/cve_upload', exist_ok=True)  # Create cve_upload with makedirs, if exists, no problem

# Write NDJSON (Newline Delimited JSON). Each line is one json
count = missing = 0
# Open ndjson
with open('/tmp/cve_upload/batch.ndjson', 'w') as out:
    for cve_id, (action, link) in latest.items():
        path = link[link.index('/cves/') + 1:]                                               # From "https://github.com/.../blob/main/cves/2026/1xxx/CVE-2026-1234.json" to "cves/2026/1xxx/CVE-2026-1234.json"
        if not os.path.exists(path):                                                         # Test Path exists
            missing += 1
            continue
        with open(path) as f:                                                                # Open path and load json
            content = json.load(f)
        out.write(json.dumps({"cve_id": cve_id, "action": action, "data": content}) + '\n')  #Write Content
        count += 1

print(f"Cves writes in batch: {count}")
if missing:
    print(f"Warnings: {missing} files not found in disk")

set_output('has_changes', 'true' if count > 0 else 'false')
