"""CLI:  python -m lab list | run [ASIxx [variant]] [--mode secure|vulnerable] | test [ASIxx] | report"""

from __future__ import annotations

import argparse
import json
import sys

from lab.registry import list_scenarios, run_scenario
from lab.runner import run_all, summarize, write_reports


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(prog="python -m lab", description="VulNet OWASP Agentic Attack Lab")
    sub = ap.add_subparsers(dest="cmd", required=True)
    sub.add_parser("list", help="list scenarios and variants")
    r = sub.add_parser("run", help="run one scenario variant in one mode and print the attack path")
    r.add_argument("scenario"); r.add_argument("variant"); r.add_argument("--mode", default="secure", choices=["secure", "vulnerable"])
    r.add_argument("--llm", action="store_true", help="let the real local Ollama model make the agent's decision")
    t = sub.add_parser("test", help="run vulnerable+secure for every variant (or one category) and print statuses")
    t.add_argument("scenario", nargs="?")
    t.add_argument("--llm", action="store_true")
    rep = sub.add_parser("report", help="run everything and write reports/")
    rep.add_argument("--out", default="reports")
    a = ap.parse_args(argv)

    if a.cmd == "list":
        for s in list_scenarios():
            print(f"{s['id']}  {s['name']}")
            for v in s["variants"]:
                print(f"    {v['id']:26} {v['title']}")
        return 0
    if a.cmd == "run":
        res = run_scenario(a.scenario, a.variant, a.mode, use_llm=a.llm)
        print(f"{res.scenario_id}/{res.variant} [{res.mode}] -> {res.outcome}  (trace {res.trace_id}, engine {res.decision_engine})")
        for s in res.steps:
            print(f"  {s['stage']:13} {s['verdict']:18} {s['component']:22} {s['detail'][:110]}")
        print("impact:", json.dumps(res.impact["ledger"]))
        return 0
    recs = run_all(a.scenario, use_llm=getattr(a, "llm", False)) if a.cmd == "test" else run_all()
    for r in recs:
        print(f"{r.status:10} {r.test_id:40} {r.security_control}")
    print(json.dumps(summarize(recs)))
    if a.cmd == "report":
        print(json.dumps(write_reports(recs, a.out), indent=2))
    return 0 if all(r.status in ("PASS", "SIMULATED") for r in recs) else 1


if __name__ == "__main__":
    sys.exit(main())
