#!/usr/bin/env python3
"""
Measure the reconnaissance channel (Gap 2 of the paper): how much a normal
tenant can learn about the cluster's node labels and taints from the
scheduler's "FailedScheduling" explanation.

Each probe is a pod in the tenant's own namespace that requests an impossible
amount of CPU, so it is never placed on any node and uses no resources. The
scheduler still explains why no node fits, e.g.
  "0/100 nodes are available: 37 node(s) didn't match Pod's node
   affinity/selector, 63 Insufficient cpu."
Nodes that pass the affinity filter and then fail on CPU are exactly the
nodes that carry the probed label, so the count leaks the label distribution.
Taint names are printed verbatim.

The tool scores what was learned against the admin's ground truth, and checks
two read channels:
  1. Events            (needs RBAC 'get/list events' in the namespace)
  2. Pod status        (the tenant can always read its own pod)
Run it once as cluster admin and once as a restricted tenant without events
access (--as-restricted) to test whether hiding events closes the channel.

SAFETY: runs only against a simulated KWOK test cluster.

Usage:
  python3 recon_probe.py --out recon.csv
  python3 recon_probe.py --as-restricted --out recon.csv
"""
import argparse
import csv
import json
import os
import re
import subprocess
import sys
import time

NS = "ns-recon"
SA = "prober"
IMPOSSIBLE_CPU = "100000"

# What a tenant might guess. Real keys from the testbed plus decoys and common
# well-known keys, so recall/precision are measured against a realistic guess list.
CANDIDATE_KEYS = ["hw.cpu", "hw.gpu", "hw.disk", "hw.mem", "hw.nic",
                  "hw.fpga", "node.kubernetes.io/instance-type",
                  "topology.kubernetes.io/zone", "kubernetes.io/arch",
                  "pool"]
CANDIDATE_VALUES = ["skylake", "cascadelake", "zen3", "zen4", "icelake",
                    "none", "t4", "a100", "h100", "v100",
                    "hdd", "ssd", "nvme",
                    "low", "med", "high",
                    "shared", "attacker", "amd64", "arm64"]

RE_TOTAL = re.compile(r"0/(\d+) nodes are available")
RE_CPU = re.compile(r"(\d+) Insufficient cpu")
RE_AFF = re.compile(r"(\d+) node\(s\) didn't match Pod's node affinity/selector")
RE_TAINT = re.compile(r"(\d+) node\(s\) had untolerated taint[^{]*\{([^}]*)\}")


def kubectl(args, stdin=None, as_user=None):
    cmd = ["kubectl"] + (["--as", as_user] if as_user else []) + args
    return subprocess.run(cmd, input=stdin, text=True, capture_output=True)


def assert_simulated_cluster():
    r = kubectl(["get", "nodes", "-o", "json"])
    if r.returncode != 0:
        sys.exit(r.stderr)
    nodes = json.loads(r.stdout)["items"]
    real = [n["metadata"]["name"] for n in nodes
            if n["metadata"].get("annotations", {})
                .get("kwok.x-k8s.io/node") != "fake"]
    if not nodes or real:
        sys.exit("Refusing to run: use only on a private KWOK simulated testbed.")
    return nodes


def ground_truth(nodes):
    labels, taints = {}, set()
    for n in nodes:
        for k, v in n["metadata"]["labels"].items():
            if k in CANDIDATE_KEYS:
                labels.setdefault(k, {}).setdefault(v, 0)
                labels[k][v] += 1
        for t in n["spec"].get("taints", []) or []:
            taints.add(f"{t['key']}: {t.get('value', '')}")
    return labels, taints


def setup_tenant(restricted):
    kubectl(["create", "namespace", NS])
    if not restricted:
        return None
    kubectl(["create", "serviceaccount", SA, "-n", NS])
    role = {
        "apiVersion": "rbac.authorization.k8s.io/v1", "kind": "Role",
        "metadata": {"name": "tenant-no-events", "namespace": NS},
        # A tenant that can manage and read its own pods, but NOT events.
        "rules": [{"apiGroups": [""], "resources": ["pods"],
                   "verbs": ["create", "get", "list", "delete"]}],
    }
    rb = {
        "apiVersion": "rbac.authorization.k8s.io/v1", "kind": "RoleBinding",
        "metadata": {"name": "tenant-no-events", "namespace": NS},
        "roleRef": {"apiGroup": "rbac.authorization.k8s.io",
                    "kind": "Role", "name": "tenant-no-events"},
        "subjects": [{"kind": "ServiceAccount", "name": SA, "namespace": NS}],
    }
    kubectl(["apply", "-f", "-"],
            stdin=json.dumps({"apiVersion": "v1", "kind": "List",
                              "items": [role, rb]}))
    return f"system:serviceaccount:{NS}:{SA}"


def probe(name, match_expr, as_user):
    spec = {"containers": [{"name": "c", "image": "registry.k8s.io/pause:3.10",
                            "resources": {"requests": {"cpu": IMPOSSIBLE_CPU}}}],
            "terminationGracePeriodSeconds": 0}
    if match_expr:
        spec["affinity"] = {"nodeAffinity": {
            "requiredDuringSchedulingIgnoredDuringExecution": {
                "nodeSelectorTerms": [{"matchExpressions": [match_expr]}]}}}
    p = {"apiVersion": "v1", "kind": "Pod",
         "metadata": {"name": name, "namespace": NS}, "spec": spec}
    kubectl(["create", "-f", "-"], stdin=json.dumps(p), as_user=as_user)

    status_msg, event_msg, event_access = "", "", True
    for _ in range(30):
        r = kubectl(["get", "pod", name, "-n", NS, "-o", "json"], as_user=as_user)
        if r.returncode == 0:
            for c in json.loads(r.stdout).get("status", {}).get("conditions", []):
                if c["type"] == "PodScheduled" and c.get("message"):
                    status_msg = c["message"]
        if status_msg:
            break
        time.sleep(1)
    r = kubectl(["get", "events", "-n", NS, "--field-selector",
                 f"involvedObject.name={name},reason=FailedScheduling",
                 "-o", "json"], as_user=as_user)
    if r.returncode != 0:
        event_access = False
    else:
        items = json.loads(r.stdout).get("items", [])
        if items:
            event_msg = items[-1].get("message", "")
    kubectl(["delete", "pod", name, "-n", NS, "--wait=false"], as_user=as_user)
    return status_msg, event_msg, event_access


def matched_nodes(msg):
    m = RE_CPU.search(msg)
    return int(m.group(1)) if m else 0


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--as-restricted", action="store_true",
                    help="probe as a tenant with no events access")
    ap.add_argument("--out", default="recon.csv")
    ap.add_argument("--log", default="recon_messages.log")
    a = ap.parse_args()

    nodes = assert_simulated_cluster()
    true_labels, true_taints = ground_truth(nodes)
    as_user = setup_tenant(a.as_restricted)
    log = open(a.log, "a")
    probes = 0
    channels = {"status": 0, "events": 0}

    def run(name, expr):
        nonlocal probes
        probes += 1
        s, e, ok = probe(name, expr, as_user)
        log.write(f"{name}\tSTATUS\t{s}\n{name}\tEVENT\t{e}\n")
        channels["status"] += bool(s)
        channels["events"] += bool(e)
        return s or e, ok

    # 1) Taints: one probe with no tolerations prints every untolerated taint.
    msg, events_ok = run("p-taints", None)
    learned_taints = {t.strip() for _, t in RE_TAINT.findall(msg)}

    # 2) Which candidate keys exist, and on how many nodes.
    learned = {}
    for i, k in enumerate(CANDIDATE_KEYS):
        msg, _ = run(f"p-key-{i}", {"key": k, "operator": "Exists"})
        if matched_nodes(msg) > 0:
            learned[k] = {}
    # 3) For each key found, which candidate values exist and their counts.
    for i, k in enumerate(learned):
        for j, v in enumerate(CANDIDATE_VALUES):
            msg, _ = run(f"p-val-{i}-{j}", {"key": k, "operator": "In", "values": [v]})
            c = matched_nodes(msg)
            if c > 0:
                learned[k][v] = c

    # ---- score against ground truth ----
    true_pairs = {(k, v) for k, vs in true_labels.items() for v in vs}
    found_pairs = {(k, v) for k, vs in learned.items() for v in vs}
    exact_counts = sum(1 for (k, v) in found_pairs & true_pairs
                       if learned[k][v] == true_labels[k][v])
    row = {
        "tenant": "restricted-no-events" if a.as_restricted else "admin",
        "nodes": len(nodes), "probes": probes,
        "events_readable": events_ok,
        "messages_via_status": channels["status"],
        "messages_via_events": channels["events"],
        "true_label_keys": len(true_labels),
        "keys_recovered": len(set(learned) & set(true_labels)),
        "true_key_value_pairs": len(true_pairs),
        "pairs_recovered": len(found_pairs & true_pairs),
        "pair_recall": round(len(found_pairs & true_pairs) / len(true_pairs), 4) if true_pairs else "",
        "node_counts_exact": exact_counts,
        "true_taints": len(true_taints),
        "taints_recovered": len(learned_taints & true_taints),
    }
    new = not os.path.exists(a.out)
    with open(a.out, "a", newline="") as f:
        w = csv.DictWriter(f, fieldnames=list(row))
        if new:
            w.writeheader()
        w.writerow(row)
    print(json.dumps(row, indent=2))
    kubectl(["delete", "namespace", NS, "--wait=false"])


if __name__ == "__main__":
    main()
