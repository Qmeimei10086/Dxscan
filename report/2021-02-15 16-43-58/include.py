import json

with open("data.json","r") as f:
    a = json.load(f)

print(a['time'])
