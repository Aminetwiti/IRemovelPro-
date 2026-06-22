import json
import os

root = r'C:\Users\amine\Downloads\[Bypassfrpfiles.com]iRemoval PRO Premium Edition 5.2\06_LOCAL_REPRODUCER\logs\v1.1\mock_server_requests.jsonl'
with open(root, 'r', encoding='utf-8') as f:
    for line in f:
        r = json.loads(line)
        print(f"  {r.get('method','?'):4s}  {r.get('path','?'):42s}  {r.get('raw_size',0):5d}B  outcome={r.get('outcome','?')}")
