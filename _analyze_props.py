import json, os, glob, sqlite3, re
from collections import Counter

base = '/tmp/dvs_workspace/dvs_7aa13bab03544516_epoch6/sessions'
all_props = []
for sf in sorted(glob.glob(base + '/*taint*.jsonl')):
    with open(sf) as f:
        lines = [l.strip() for l in f if l.strip()]
    for line in lines:
        ev = json.loads(line)
        msg = ev.get('message', {})
        if msg.get('role') == 'assistant':
            for c in msg.get('content', []):
                if c.get('type') == 'text':
                    text = c.get('text', '')
                    # Extract JSON from ```json blocks
                    m = re.search(r'```json\s*(\{.*?\})\s*```', text, re.DOTALL)
                    if not m:
                        m = re.search(r'(\{.*\})', text, re.DOTALL)
                    if m:
                        try:
                            obj = json.loads(m.group(1))
                            if 'propagations' in obj:
                                for p in obj['propagations']:
                                    p['_session'] = os.path.basename(sf)
                                    all_props.append(p)
                        except:
                            pass

print('Total propagations:', len(all_props))
target_funcs = Counter(p.get('target_function','') for p in all_props)
print()
print('=== Top target functions ===')
for f, c in target_funcs.most_common(20):
    print('  %3d %s' % (c, f))

ext = [p for p in all_props if p.get('is_external')]
print()
print('External/escape:', len(ext))
for p in ext[:10]:
    print('  %s -> %s via=%s carrier=%s' % (p.get('source_taint','')[:20], p.get('target_taint','')[:30], p.get('escape_via',''), p.get('carrier','')))

fc = sqlite3.connect('/tmp/dvs_workspace/dvs_7aa13bab03544516_epoch6/dataflow-v2/functions.db')
known = set(r[0] for r in fc.execute('SELECT name FROM functions').fetchall())
fc.close()
unknown = [p for p in all_props if p.get('target_function','') and p.get('target_function') not in known]
print()
print('External lib targets:', len(unknown))
for p in unknown[:10]:
    print('  %s -> %s' % (p.get('source_taint','')[:20], p.get('target_function','')[:30]))

ret = [p for p in all_props if p.get('target_taint','') in ('ret','return')]
print()
print('Return taint propagations:', len(ret))

# Check propagations to functions that are just "request" parameter pass-through
passthrough = [p for p in all_props if p.get('source_taint','') == p.get('target_taint','') and not p.get('is_external')]
print()
print('Same-name passthrough (source_taint == target_taint):', len(passthrough))
for p in passthrough[:10]:
    print('  %s -> %s(%s) desc=%s' % (p.get('source_taint','')[:20], p.get('target_function','')[:30], p.get('target_taint','')[:20], p.get('description','')[:50]))
