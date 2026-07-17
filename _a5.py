import json, os, glob, sqlite3, re
from collections import Counter, defaultdict

base = '/tmp/dvs_workspace/dvs_7aa13bab03544516_epoch6'
sessions = sorted(glob.glob(base + '/sessions/*taint*.jsonl'))

all_props = []
for sf in sessions:
    with open(sf) as f:
        lines = [l.strip() for l in f if l.strip()]
    target_func = ''
    for line in lines:
        ev = json.loads(line)
        msg = ev.get('message', {})
        if msg.get('role') == 'user':
            for c in msg.get('content', []):
                if c.get('type') == 'text':
                    text = c.get('text', '')
                    m = re.search(r'目标函数:.*?::(\w+)', text)
                    if m: target_func = m.group(1)
        if msg.get('role') == 'assistant':
            for c in msg.get('content', []):
                if c.get('type') == 'text':
                    text = c.get('text', '')
                    m = re.search(r'```json\s*(\{.*?\})\s*```', text, re.DOTALL)
                    if not m:
                        m = re.search(r'(\{.*\})', text, re.DOTALL)
                    if m:
                        try:
                            obj = json.loads(m.group(1))
                            for p in obj.get('propagations', []):
                                p['_source_func'] = target_func
                                p['_session'] = os.path.basename(sf)
                                all_props.append(p)
                        except: pass

escapes = [p for p in all_props if p.get('is_external')]
print('Total escape propagations:', len(escapes))
print()

via_counter = Counter(p.get('escape_via','') for p in escapes)
print('=== Escape via ===')
for v, c in via_counter.most_common():
    print('  %3d %s' % (c, v or '(none)'))

carrier_counter = Counter(p.get('carrier','') for p in escapes)
print()
print('=== Escape carrier ===')
for c, cnt in carrier_counter.most_common(10):
    print('  %3d %s' % (cnt, c or '(none)'))

tt_counter = Counter(p.get('target_taint','') for p in escapes)
print()
print('=== Escape target_taint ===')
for t, c in tt_counter.most_common(10):
    print('  %3d %s' % (c, t or '(none)'))

print()
print('=== Escape patterns by source function ===')
esc_by_func = defaultdict(list)
for p in escapes:
    esc_by_func[p['_source_func']].append(p)
for f, props in sorted(esc_by_func.items(), key=lambda x: -len(x[1])):
    vias = set(p.get('escape_via','') for p in props)
    carriers = set(p.get('carrier','') for p in props)
    print('  %s: %d escapes via=%s carriers=%s' % (f, len(props), list(vias)[:3], list(carriers)[:3]))

same_name_in_tree = [p for p in all_props if not p.get('is_external') and p.get('source_taint','') == p.get('target_taint','') and p.get('target_function','').startswith('_')]
print()
print('=== Same-name passthrough to in-tree functions:', len(same_name_in_tree), '===')
func_counter = Counter(p['target_function'] for p in same_name_in_tree)
for f, c in func_counter.most_common(10):
    print('  %3d -> %s' % (c, f))
    taints = set(p['source_taint'] for p in same_name_in_tree if p['target_function'] == f)
    print('       taints: %s' % list(taints)[:5])

# Count how many sessions are just re-analyzing the same function with same taint
# but from different call paths (now deduped, but check vuln sessions)
vuln_sessions = [sf for sf in sessions if '-vuln-' in os.path.basename(sf)]
print()
print('Total vuln (mining) sessions:', len(vuln_sessions))
print('Total taint sessions:', len(sessions) - len(vuln_sessions))

# Check: functions tracked at depth 3 that are just "request" passthrough
d3_request = [sf for sf in sessions if 'd03-' in os.path.basename(sf) and 'request' in os.path.basename(sf)]
print()
print('d03 sessions with "request" taint:', len(d3_request))
for sf in d3_request[:10]:
    print('  ', os.path.basename(sf))
