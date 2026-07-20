import re, json

text = '```json\n{\n  "description": "处理UE发送的Activate Dedicated EPS Bearer Context Accept消息",\n  "self_contained": false,\n  "taints": [\n    { "name": "msgBuf", "description": "UE发送的NAS消息缓冲区，攻击者可控" },\n    { "name": "actBrAccpt", "description": "由msgBuf强转而来的消息结构体指针" },\n    { "name": "actBrAccpt->epsBearerIdentity", "description": "EPS承载标识" }\n  ],\n  "propagations": [\n    {\n      "source_taint": "actBrAccpt->epsBearerIdentity",\n      "target_taint": "bearId",\n      "target_function": "RelayEmmCheckBearStat",\n      "validations": [\n        { "left": "bearPos", "op": ">=", "right": "VOS_Min(userTable->esmInfo.erabTable.bearInfo.cnt, ESM_MAX_BEAR_NUM)", "line": 909 }\n      ],\n      "description": "epsBearerIdentity作为查找键",\n      "is_external": false\n    }\n  ],\n  "return_taints": []\n}\n```'

# Test 1: code block regex
code_match = re.search(r"```(?:json)?\s*\n(.*?)\n\s*```", text, re.DOTALL)
if code_match:
    try:
        obj = json.loads(code_match.group(1))
        print("Code block match: SUCCESS")
        print("  has propagations:", "propagations" in obj)
        print("  propagations count:", len(obj.get("propagations", [])))
    except json.JSONDecodeError as e:
        print(f"Code block match: JSON PARSE FAILED: {e}")
        print(f"  matched text (last 200 chars): ...{code_match.group(1)[-200:]}")
else:
    print("Code block regex: NO MATCH")
    # Debug: check what the regex sees
    print("  text starts with:", repr(text[:50]))
    print("  text ends with:", repr(text[-50:]))

# Test 2: direct json.loads of the full text
print("\n--- Direct json.loads ---")
try:
    # strip code block markers
    stripped = text.strip()
    if stripped.startswith('```'):
        lines = stripped.split('\n')
        # Remove first line (```json) and last line (```)
        json_text = '\n'.join(lines[1:-1])
        obj = json.loads(json_text)
        print("Direct parse: SUCCESS")
        print("  propagations:", len(obj.get("propagations",[])))
    else:
        print("Not a code block")
except Exception as e:
    print(f"Direct parse: FAILED: {e}")

# Test 3: Check if the issue is with the regex specifically
print("\n--- Regex debug ---")
# The regex is: r"```(?:json)?\s*\n(.*?)\n\s*```"
# Let's check each part
print("Has ```:", '```' in text)
print("Has ```json:", '```json' in text)
# Find all ``` positions
for m in re.finditer('```', text):
    print(f"  ``` at pos {m.start()}: context={repr(text[m.start():m.start()+15])}")
