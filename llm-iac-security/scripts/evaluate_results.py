#!/usr/bin/env python3
import json, sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

GT = Path("tests/fixtures/ground_truth/annotations.json")

def metrics(detected, truth):
    tp = len(set(detected) & set(truth)); fp = len(set(detected)-set(truth)); fn = len(set(truth)-set(detected))
    p = tp/(tp+fp) if tp+fp else 0.0; r = tp/(tp+fn) if tp+fn else 0.0
    f1 = 2*p*r/(p+r) if p+r else 0.0
    return {"precision": round(p,4), "recall": round(r,4), "f1": round(f1,4)}

if __name__ == "__main__":
    if not GT.exists(): print(f"Ground truth not found: {GT}"); sys.exit(1)
    data = json.loads(GT.read_text())
    all_d, all_t = [], []
    for tid, entry in data.items():
        t, d = entry.get("known_vulnerabilities",[]), entry.get("detected_vulnerabilities",[])
        m = metrics(d, t)
        print(f"{tid}: P={m['precision']:.2%} R={m['recall']:.2%} F1={m['f1']:.2%}")
        all_d.extend(d); all_t.extend(t)
    o = metrics(all_d, all_t)
    print(f"\nOverall: P={o['precision']:.2%} R={o['recall']:.2%} F1={o['f1']:.2%}")
