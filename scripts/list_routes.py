import re

with open("src/web/server.rs", "r", encoding="utf-8") as f:
    for line in f:
        m = re.search(r'\("(GET|POST)",\s*"([^"]+)"\)', line)
        if m:
            print(f"{m.group(1)} {m.group(2)}")
