import json
from pathlib import Path

def load_fs():
    path = Path(__file__).parent / "fake_fs.json"
    with open(path) as f:
        return json.load(f)
