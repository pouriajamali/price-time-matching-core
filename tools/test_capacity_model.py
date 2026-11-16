"""Finite manual goldens against the independent dictionary model; no C# import.

--matrix runs exactly the normal, -O and PYTHONOPTIMIZE=1 workers once each.
--check-matrix only checks the resulting identity/count/mode partition; no replay.
This module is source-prepared, not an admission or a claim of execution.
"""
import argparse
import copy
import hashlib
import json
import os
from pathlib import Path
import platform
import re
import subprocess
import sys

import oracle

MODES = ("normal", "-O", "PYTHONOPTIMIZE=1")
NEGATIVES = ("rejected-result-sequence", "snapshot-sequence", "maker-id", "trade-order",
             "trade-price", "trade-quantity", "remaining-quantity", "priority-array",
             "missing-state", "extra-state", "resting-zero", "lifetime-below-resting")
ORDER_KEYS = {"orderId", "side", "priceTicks", "acceptedSequence", "acceptedQuantity",
              "remainingQuantity", "executedQuantity", "cancelledQuantity"}
STATE_KEYS = {"acceptedSequence", "acceptedQuantity", "executedQuantity", "cancelledQuantity",
              "executedNotional", "orders", "bidPriority", "askPriority"}
RESULT_KEYS = {"status", "reason", "acceptedSequence", "trades"}
COMMAND_KEYS = {"kind", "orderId", "side", "priceTicks", "quantity"}
TRADE_KEYS = {"tradeId", "makerId", "takerId", "priceTicks", "quantity"}


def require(condition, message):
    if not condition:
        raise ValueError(message)


def keys(value, expected, where):
    require(type(value) is dict and set(value) == expected, "Exact fields: " + where)


def integer(value, minimum=0, maximum=2**63 - 1):
    require(type(value) is int and minimum <= value <= maximum, "Integer domain")


def identity(value):
    require(type(value) is str and re.fullmatch(r"[a-z0-9][a-z0-9-]{0,31}", value), "ID domain")


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("ascii")


def shape(trace):
    keys(trace, {"id", "resting", "lifetimeIds", "steps"}, "trace")
    require(type(trace["id"]) is str, "Trace identity")
    integer(trace["resting"], 1, 10000)
    integer(trace["lifetimeIds"], trace["resting"], 100000)
    require((trace["resting"], trace["lifetimeIds"]) in ((1, 8), (2, 8), (1, 2)), "Finite Limits")
    require(type(trace["steps"]) is list and 1 <= len(trace["steps"]) <= 16, "Step cap")
    for step in trace["steps"]:
        keys(step, {"command", "result", "snapshot"}, "step")
        command, result, state = step["command"], step["result"], step["snapshot"]
        keys(command, COMMAND_KEYS, "command")
        identity(command["orderId"])
        require(command["kind"] in ("limit", "cancel"), "Command kind")
        if command["kind"] == "limit":
            require(command["side"] in ("buy", "sell"), "Command side")
            integer(command["priceTicks"], 80, 120)
            integer(command["quantity"], 1, 4)
        else:
            require(all(command[k] is None for k in ("side", "priceTicks", "quantity")), "Cancel fields")
        keys(result, RESULT_KEYS, "result")
        require(result["status"] in ("ACCEPTED", "REJECTED") and type(result["reason"]) is str, "Result domain")
        integer(result["acceptedSequence"])
        require(type(result["trades"]) is list and len(result["trades"]) <= 2, "Trade cap")
        for trade in result["trades"]:
            keys(trade, TRADE_KEYS, "trade")
            require(type(trade["tradeId"]) is str and re.fullmatch(r"[1-9][0-9]*:[1-9][0-9]*", trade["tradeId"]), "Trade ID")
            identity(trade["makerId"])
            identity(trade["takerId"])
            integer(trade["priceTicks"], 80, 120)
            integer(trade["quantity"], 1, 4)
        keys(state, STATE_KEYS, "snapshot")
        for key in STATE_KEYS - {"orders", "bidPriority", "askPriority"}:
            integer(state[key])
        require(type(state["orders"]) is list and len(state["orders"]) <= trace["lifetimeIds"], "Ledger cap")
        for order in state["orders"]:
            keys(order, ORDER_KEYS, "order")
            identity(order["orderId"])
            require(order["side"] in ("buy", "sell"), "Order side")
            integer(order["priceTicks"], 80, 120)
            for key in ORDER_KEYS - {"orderId", "side", "priceTicks"}:
                integer(order[key])
        for side in ("bidPriority", "askPriority"):
            require(type(state[side]) is list and len(state[side]) <= trace["resting"], "Priority cap")
            for item in state[side]:
                identity(item)


def verify_trace(trace, budget):
    shape(trace)
    model = oracle.Model(trace["resting"], trace["lifetimeIds"])
    for number, step in enumerate(trace["steps"], 1):
        before = canonical(model.snapshot())
        budget[0] += 1
        require(budget[0] <= 384, "Per-mode model application cap")
        actual = model.apply(step["command"])
        state = model.snapshot()  # Also checks conservation and uncrossed book independently.
        require(actual == step["result"], "Result mismatch: " + trace["id"] + "/" + str(number))
        require(state == step["snapshot"], "Full state mismatch: " + trace["id"] + "/" + str(number))
        require(actual["acceptedSequence"] == state["acceptedSequence"], "Result/state sequence")
        if actual["status"] == "REJECTED":
            require(actual["trades"] == [] and canonical(state) == before, "Atomic rejection")


def corrupt(traces, name):
    trace = copy.deepcopy(next(t for t in traces if t["id"] == ("F-direct" if name in
        ("maker-id", "trade-order", "trade-price", "trade-quantity", "missing-state", "extra-state")
        else "B-direct" if name == "lifetime-below-resting" else "A-direct")))
    if name == "rejected-result-sequence":
        trace["steps"][1]["result"]["acceptedSequence"] += 1
    elif name == "snapshot-sequence":
        trace["steps"][1]["snapshot"]["acceptedSequence"] += 1
    elif name == "maker-id":
        trace["steps"][4]["result"]["trades"][0]["makerId"] = "wrong"
    elif name == "trade-order":
        trace["steps"][4]["result"]["trades"].reverse()
    elif name == "trade-price":
        trace["steps"][4]["result"]["trades"][0]["priceTicks"] += 1
    elif name == "trade-quantity":
        trace["steps"][4]["result"]["trades"][0]["quantity"] += 1
    elif name == "remaining-quantity":
        trace["steps"][0]["snapshot"]["orders"][0]["remainingQuantity"] += 1
    elif name == "priority-array":
        trace["steps"][0]["snapshot"]["bidPriority"] = []
    elif name == "missing-state":
        del trace["steps"][-1]["snapshot"]
    elif name == "extra-state":
        trace["steps"][-1]["extraSnapshot"] = copy.deepcopy(trace["steps"][-1]["snapshot"])
    elif name == "resting-zero":
        trace["resting"] = 0
    elif name == "lifetime-below-resting":
        trace["lifetimeIds"] = 1
    else:
        raise ValueError("Unknown corruption")
    return trace


def unique_pairs(pairs):
    result = {}
    for key, value in pairs:
        require(key not in result, "Duplicate JSON field")
        result[key] = value
    return result


def load(path):
    raw = path.read_bytes()
    require(1 <= len(raw) <= 256 * 1024, "Fixture byte cap")
    data = json.loads(raw.decode("utf-8"), object_pairs_hook=unique_pairs)
    keys(data, {"schema", "authorship", "traces"}, "document")
    require(data["schema"] == "matching-capacity-goldens/v1" and type(data["authorship"]) is str, "Fixture schema")
    require(type(data["traces"]) is list and len(data["traces"]) == 12, "Exact trace partition")
    require([t.get("id") for t in data["traces"]] == [n + s for n in "ABCDEF" for s in ("-direct", "-mirror")], "Trace identities/order")
    for trace in data["traces"]:
        shape(trace)
    count = sum(len(t["steps"]) for t in data["traces"])
    require(count <= 192, "Base command cap")
    return data, hashlib.sha256(raw).hexdigest(), count


def write_new(path, value):
    with path.open("x", encoding="utf-8", newline="\n") as stream:
        json.dump(value, stream, indent=2)
        stream.write("\n")


def worker(fixtures, out, mode):
    require(sys.version_info >= (3, 12), "Python3.12 minimum")
    require(sys.flags.optimize == (0 if mode == "normal" else 1), "Actual interpreter optimization mode")
    require((os.environ.get("PYTHONOPTIMIZE") == "1") == (mode == "PYTHONOPTIMIZE=1"), "Interpreter environment partition")
    doc, digest, commands = load(fixtures)
    budget = [0]
    for trace in doc["traces"]:
        verify_trace(trace, budget)
    denials = []
    for name in NEGATIVES:
        try:
            verify_trace(corrupt(doc["traces"], name), budget)
        except ValueError as failure:
            denials.append({"case": name, "reason": str(failure)})
        else:
            raise ValueError("Accepted corrupt golden: " + name)
    write_new(out, {"schema": "matching-capacity-python/v1", "status": "PASS", "mode": mode,
                   "pythonVersion": platform.python_version(), "optimized": sys.flags.optimize,
                   "fixtureSha256": digest, "verifierSha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
                   "traces": 12, "baseCommands": commands, "applications": budget[0], "denials": denials})


def check_matrix(fixtures, directory):
    _, digest, commands = load(fixtures)
    source = hashlib.sha256(Path(__file__).read_bytes()).hexdigest()
    require({p.name for p in directory.iterdir()} == {"mode-0.json", "mode-1.json", "mode-2.json", "matrix.json"}, "Exact matrix files")
    total = 0
    for index, mode in enumerate(MODES):
        receipt = json.loads((directory / ("mode-" + str(index) + ".json")).read_text())
        require(receipt["schema"] == "matching-capacity-python/v1" and receipt["status"] == "PASS", "Worker receipt")
        require(receipt["fixtureSha256"] == digest and receipt["verifierSha256"] == source, "Worker input/source identity")
        require(receipt["mode"] == mode and receipt["optimized"] == (0 if index == 0 else 1), "Exact mode")
        require(receipt["traces"] == 12 and receipt["baseCommands"] == commands, "Worker membership")
        require([x["case"] for x in receipt["denials"]] == list(NEGATIVES), "Negative membership")
        integer(receipt["applications"], commands, 384)
        total += receipt["applications"]
    require(total <= 1152, "All-three-modes application cap")
    aggregate = json.loads((directory / "matrix.json").read_text())
    require(aggregate == {"schema": "matching-capacity-matrix/v1", "status": "PASS", "modes": list(MODES),
                          "fixtureSha256": digest, "applications": total}, "Exact matrix aggregate")
    return total


def matrix(fixtures, out):
    require(sys.version_info >= (3, 12), "Python3.12 minimum")
    _, digest, _ = load(fixtures)
    out.mkdir(parents=True, exist_ok=False)
    for index, mode in enumerate(MODES):
        env = os.environ.copy()
        env.pop("PYTHONOPTIMIZE", None)
        if mode == "PYTHONOPTIMIZE=1":
            env["PYTHONOPTIMIZE"] = "1"
        args = [sys.executable] + (["-O"] if mode == "-O" else []) + [str(Path(__file__).resolve()),
                "--fixtures", str(fixtures), "--out", str(out / ("mode-" + str(index) + ".json")), "--worker=" + mode]
        completed = subprocess.run(args, env=env, timeout=45, check=False, stdout=subprocess.DEVNULL)
        require(completed.returncode == 0, "Worker failed: " + mode)
    total = sum(json.loads((out / ("mode-" + str(i) + ".json")).read_text())["applications"] for i in range(3))
    write_new(out / "matrix.json", {"schema": "matching-capacity-matrix/v1", "status": "PASS",
                                  "modes": list(MODES), "fixtureSha256": digest, "applications": total})
    check_matrix(fixtures, out)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--fixtures", type=Path, required=True)
    parser.add_argument("--out", type=Path, required=True)
    action = parser.add_mutually_exclusive_group(required=True)
    action.add_argument("--matrix", action="store_true")
    action.add_argument("--check-matrix", action="store_true")
    action.add_argument("--worker", choices=MODES)
    args = parser.parse_args()
    if args.matrix:
        matrix(args.fixtures.resolve(), args.out.resolve())
    elif args.check_matrix:
        check_matrix(args.fixtures.resolve(), args.out.resolve())
    else:
        worker(args.fixtures.resolve(), args.out.resolve(), args.worker)


if __name__ == "__main__":
    main()
