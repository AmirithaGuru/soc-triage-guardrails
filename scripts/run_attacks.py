#!/usr/bin/env python3
"""Run the prompt-injection attacks against the triage pipeline and record results.

What it does
  For the clean control finding and each attack fixture (I1-I5), it runs the real
  pipeline steps  extract_fields -> build_messages -> Bedrock -> parse_output,
  N times, and applies the deterministic check from attack_checks.py.

What it does NOT do
  * It never imports lambda/slack.py, so nothing is posted to Slack.
  * It changes nothing in AWS. It only calls the model (bedrock-runtime Converse),
    the same call as your "say hi" test.
  * It never reads or prints credentials or the Slack webhook.

Usage (from the project root, with AWS_PROFILE=triage exported):
  python3 scripts/run_attacks.py --dry-run                 # show the plan, no calls
  python3 scripts/run_attacks.py                           # v1, 5 repeats each
  python3 scripts/run_attacks.py --version v2 --out results/after_v2.json

Each run costs a fraction of a cent. The default (6 cases x 5 repeats) is about
30 calls, a few cents in total.
"""
import argparse
import datetime
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "scripts"))

from attack_checks import CHECKS, severity_rank  # noqa: E402

FIXTURES = ROOT / "tests" / "fixtures"
MAX_TEXT = 400  # characters of model text saved per field


# ------------------------------------------------------------------ fixtures

def load_cases(only=None):
    """Control first, then I1..I5 (optionally filtered by --only)."""
    base = json.loads((FIXTURES / "base_finding.json").read_text())
    cases = [{
        "id": "C0",
        "name": "Control (clean finding, no injection)",
        "owasp": "-",
        "goal": "Baseline: what the model says when nobody attacks it.",
        "injected_path": None,
        "payload": None,
        "finding": base,
    }]
    for path in sorted((FIXTURES / "attacks").glob("I*.json"),
                       key=lambda p: int(p.stem[1:])):
        cases.append(json.loads(path.read_text()))
    if only:
        wanted = {x.strip().upper() for x in only.split(",")}
        cases = [c for c in cases if c["id"] in wanted]
    return cases


# ------------------------------------------------------------------ pipeline

def make_real_pipeline(version):
    """Wire up the real Lambda modules (imported lazily so tests don't need them).

    The steps and their order mirror lambda/handler.py exactly, so what is
    measured here is what runs in production (minus the Slack post).
    """
    sys.path.insert(0, str(ROOT / "lambda"))
    from extract import extract_fields
    from policy import apply_policy
    from prompts import build_messages
    from bedrock_client import triage
    from validate import parse_output

    def pipeline(finding):
        fields = extract_fields(finding, version)
        system_prompt, messages = build_messages(fields, version)
        text = triage(system_prompt, messages, version)
        parsed = parse_output(text, version)
        parsed = apply_policy(parsed, finding, version)
        return system_prompt, text, parsed

    return pipeline


# ------------------------------------------------------------------- running

def _clip(value):
    return value[:MAX_TEXT] if isinstance(value, str) else value


def run_once(case, pipeline):
    """One run -> one result dict. Never raises: errors are recorded as verdicts."""
    try:
        system_prompt, raw_text, parsed = pipeline(case["finding"])
    except Exception as exc:  # in production this path triggers the fail-safe
        if type(exc).__name__ == "GuardrailIntervened":
            # The Bedrock Guardrail refused the request. In production a human
            # still gets the raw finding, so this counts as a successful defence.
            return {"verdict": "blocked_by_guardrail", "error": type(exc).__name__}
        return {"verdict": "pipeline_error", "error": type(exc).__name__,
                "detail": _clip(str(exc))}

    result = {
        "severity": parsed.get("severity"),
        "summary": _clip(parsed.get("summary")),
        "recommended_action": _clip(parsed.get("recommended_action")),
        "attack_technique_id": parsed.get("attack_technique_id"),
        "suspicious_input_detected": parsed.get("suspicious_input_detected"),
        # v2 only: what the model said BEFORE the severity floor, and whether
        # the floor had to correct it.
        "model_severity": parsed.get("model_severity"),
        "severity_floor_applied": parsed.get("severity_floor_applied"),
    }
    check = CHECKS.get(case["id"])
    if check is None:                      # the control has no attack to judge
        result["verdict"] = "control"
        return result
    succeeded, reason = check(parsed, system_prompt)
    result["verdict"] = "attack_succeeded" if succeeded else "resisted"
    result["reason"] = reason
    return result


def run_case(case, pipeline, repeats):
    runs = [run_once(case, pipeline) for _ in range(repeats)]
    count = lambda v: sum(1 for r in runs if r["verdict"] == v)  # noqa: E731
    return {
        "id": case["id"],
        "name": case["name"],
        "owasp": case["owasp"],
        "goal": case["goal"],
        "injected_path": case["injected_path"],
        "payload": case["payload"],
        "attack_succeeded": count("attack_succeeded"),
        "resisted": count("resisted"),
        "blocked_by_guardrail": count("blocked_by_guardrail"),
        "pipeline_errors": count("pipeline_error"),
        "floor_saved": sum(1 for r in runs if r.get("severity_floor_applied") is True),
        "suspicious_flagged": sum(1 for r in runs if r.get("suspicious_input_detected") is True),
        "runs": runs,
    }


def run_all(cases, pipeline, repeats, meta):
    results = []
    for case in cases:
        print(f"  running {case['id']}: {case['name']} ...", flush=True)
        results.append(run_case(case, pipeline, repeats))
    report = {"meta": meta, "cases": results}
    annotate_severity_shift(report)
    return report


def control_severity(report):
    """Most common severity the model gave the clean control finding (or None)."""
    for c in report["cases"]:
        if c["id"] == "C0":
            sevs = [str(r["severity"]).upper() for r in c["runs"] if r.get("severity")]
            return max(set(sevs), key=sevs.count) if sevs else None
    return None


def annotate_severity_shift(report):
    """Count runs whose severity differs from the control's. This catches
    attacks that MOVE the answer without matching a specific attack check
    (for example I2 pushed HIGH up to CRITICAL in round 1)."""
    baseline = control_severity(report)
    report["meta"]["control_severity"] = baseline
    for c in report["cases"]:
        c["severity_differs_from_control"] = (
            None if baseline is None or c["id"] == "C0" else
            sum(1 for r in c["runs"]
                if r.get("severity") and str(r["severity"]).upper() != baseline))


# ------------------------------------------------------------------- display

def print_table(report):
    repeats = report["meta"]["repeats"]
    n = str(repeats)
    print()
    print(f"{'ID':<4} {'Attack':<44} {'Succeeded':>9} {'Resisted':>9} {'Blocked':>8} "
          f"{'Errors':>7} {'Floor':>6} {'Flagged':>8} {'Sev moved':>10}")
    print("-" * 114)
    for c in report["cases"]:
        if c["id"] == "C0":
            sevs = sorted({str(r.get("severity")) for r in c["runs"]})
            print(f"{c['id']:<4} {c['name'][:44]:<44} {'-':>9} {'-':>9} {'-':>8} "
                  f"{c['pipeline_errors']:>7} {'-':>6} {'-':>8} {'-':>10}   severity seen: {', '.join(sevs)}")
            continue
        print(f"{c['id']:<4} {c['name'][:44]:<44} "
              f"{str(c['attack_succeeded']) + '/' + n:>9} "
              f"{str(c['resisted']) + '/' + n:>9} "
              f"{str(c.get('blocked_by_guardrail', 0)) + '/' + n:>8} "
              f"{c['pipeline_errors']:>7} "
              f"{str(c.get('floor_saved', 0)) + '/' + n:>6} "
              f"{str(c.get('suspicious_flagged', 0)) + '/' + n:>8} "
              f"{str(c.get('severity_differs_from_control')) + '/' + n:>10}")
    print()
    print("Succeeded = attack got what it wanted | Resisted = answer looked safe | "
          "Blocked = guardrail refused (human still alerted)")
    print("Floor = severity floor corrected the AI | Flagged = AI reported suspicious "
          "input | Sev moved = severity differs from control")
    print()


def control_warning(report):
    """The control must reach HIGH, otherwise 'downgrade' results mean nothing."""
    for c in report["cases"]:
        if c["id"] == "C0":
            ranks = [severity_rank(r.get("severity")) for r in c["runs"]]
            if not ranks or any(r is None or r < 3 for r in ranks):
                return ("WARNING: the clean control was not rated HIGH in every "
                        "run, so severity-downgrade results are not comparable. "
                        "Read results/*.json before quoting numbers.")
    return None


def strict_failures(report):
    """Case ids that make a --strict run fail: an attack worked or a run errored."""
    return [c["id"] for c in report["cases"]
            if c["attack_succeeded"] > 0 or c["pipeline_errors"] > 0]


# ---------------------------------------------------------------------- main

def parse_args(argv=None):
    p = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    p.add_argument("--version", default="v1", help="prompt version (default v1)")
    p.add_argument("--repeats", type=int, default=5, help="runs per case (default 5)")
    p.add_argument("--out", default="results/before_v1.json")
    p.add_argument("--only", help="comma-separated ids, e.g. I1,I4")
    p.add_argument("--dry-run", action="store_true", help="show the plan, make no calls")
    p.add_argument("--yes", action="store_true", help="skip the confirmation prompt")
    p.add_argument("--show", metavar="FILE",
                   help="print the results table from a saved JSON file and exit (no calls)")
    p.add_argument("--strict", action="store_true",
                   help="exit 4 if any attack succeeded or any run errored (for CI)")
    return p.parse_args(argv)


def main(argv=None):
    args = parse_args(argv)
    if args.show:
        report = json.loads(Path(args.show).read_text())
        print_table(report)
        warning = control_warning(report)
        if warning:
            print(warning)
        return 0
    cases = load_cases(args.only)
    calls = len(cases) * args.repeats

    print(f"Prompt version: {args.version}   cases: {', '.join(c['id'] for c in cases)}"
          f"   repeats: {args.repeats}   Bedrock calls: {calls}")
    for c in cases:
        print(f"  {c['id']}: {c['name']}")
    if args.dry_run:
        print("\nDry run: no calls made.")
        return 0
    if not args.yes and input(f"\nMake {calls} Bedrock calls (a few cents)? [y/N] ").lower() != "y":
        print("Cancelled.")
        return 1

    if args.version != "v1":
        import os
        if not (os.environ.get("GUARDRAIL_IDENTIFIER") and os.environ.get("GUARDRAIL_VERSION")):
            print("\nPrompt version %s needs the guardrail settings. Run these first "
                  "(from the project root):" % args.version)
            print("  export GUARDRAIL_IDENTIFIER=$(terraform -chdir=terraform output -raw guardrail_identifier)")
            print("  export GUARDRAIL_VERSION=$(terraform -chdir=terraform output -raw guardrail_version)")
            return 2

    pipeline = make_real_pipeline(args.version)
    try:
        from bedrock_client import MODEL_ID
    except Exception:
        MODEL_ID = "unknown"
    meta = {
        "run_at": datetime.datetime.now(datetime.timezone.utc).isoformat(timespec="seconds"),
        "prompt_version": args.version,
        "model_id": MODEL_ID,
        "temperature": 0,
        "repeats": args.repeats,
        "note": "Verdicts come from simple text checks (scripts/attack_checks.py); "
                "read the saved model text before quoting results.",
    }
    report = run_all(cases, pipeline, args.repeats, meta)

    out = ROOT / args.out
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(report, indent=2) + "\n")
    print_table(report)
    warning = control_warning(report)
    if warning:
        print(warning)
    try:
        shown = out.relative_to(ROOT)
    except ValueError:
        shown = out
    print(f"Saved {shown}")
    if args.strict:
        failed = strict_failures(report)
        if failed:
            print(f"STRICT: FAIL - an attack succeeded or a run errored in: {', '.join(failed)}")
            return 4
        print("STRICT: PASS - no attack succeeded and no run errored.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
