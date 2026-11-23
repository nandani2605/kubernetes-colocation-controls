#!/usr/bin/env python3
"""
One run of the co-location experiment (Section X of the paper).

Measures whether Kubernetes-native controls reduce the success of a tenant
that copies a victim's placement requests, and what each control costs
legitimate tenants.

Conditions (Table VI of the paper):
  C0  default scheduler, no extra control (baseline)
  C1  ResourceQuota with the CrossNamespacePodAffinity scope, limit 0,
      in the attacker namespace
  C2  per-tenant node pools: shared tenants and the attacker tenant are
      kept on disjoint, tainted node pools (the outcome PodTolerationRestriction
      + PodNodeSelector enforce in production)
  C3  ValidatingAdmissionPolicy that limits which node-label keys any tenant
      namespace may request (built into Kubernetes; no Gatekeeper needed)

Attacker modes:
  node  copy the victim's required node affinity, request minimal resources,
        and spread own replicas with pod anti-affinity (REPTTACK [13])
  pod   require pod affinity to the victim's pods across namespaces
        (only possible if the attacker knows the victim's pod labels)

Ground truth: pod.spec.nodeName. A victim counts as co-located if at least
one of its attacker pods is bound to the same node.

SAFETY: this script runs only against a simulated KWOK test cluster. It aborts
if any node in the cluster is not a KWOK fake node.

Usage:
  python3 run_experiment.py --condition C0 --mode node --seed 1 --out results.csv
"""
import argparse
import csv
import json
import math
import os
import random
import subprocess
import sys
import time
from datetime import datetime

NS_V, NS_B, NS_A = "ns-victims", "ns-background", "ns-attacker"
TENANT_NAMESPACES = [NS_V, NS_B, NS_A]
PAUSE = "registry.k8s.io/pause:3.10"
VAP_NAME = "restrict-node-labels"
QUOTA_NAME = "no-cross-ns-affinity"


# ----------------------------------------------------------------- kubectl --
def kubectl(args, stdin=None, check=False):
    r = subprocess.run(["kubectl", *args], input=stdin, text=True,
                       capture_output=True)
    if check and r.returncode != 0:
        sys.exit(f"kubectl {' '.join(args)} failed:\n{r.stderr}")
    return r


def kjson(args):
    r = kubectl([*args, "-o", "json"], check=True)
    return json.loads(r.stdout)


def apply_list(items, verb="create"):
    """Submit many objects in one call. Denied items are reported by the
    API server and skipped; we count them afterwards by listing what exists."""
    if not items:
        return
    doc = json.dumps({"apiVersion": "v1", "kind": "List", "items": items})
    kubectl([verb, "-f", "-"], stdin=doc)


# ------------------------------------------------------------------ safety --
def assert_simulated_cluster():
    nodes = kjson(["get", "nodes"])["items"]
    if not nodes:
        sys.exit("No nodes. Run make_nodes.py first.")
    real = [n["metadata"]["name"] for n in nodes
            if n["metadata"].get("annotations", {})
                .get("kwok.x-k8s.io/node") != "fake"]
    if real:
        sys.exit("Refusing to run: these nodes are not KWOK simulated nodes: "
                 f"{real[:5]}... This tool is for a private simulated testbed "
                 "only (see the paper's ethics note).")
    return nodes


# --------------------------------------------------------------- manifests --
def pod(name, ns, labels, cpu, mem, affinity=None, tolerations=None):
    spec = {
        "containers": [{
            "name": "c", "image": PAUSE,
            "resources": {"requests": {"cpu": cpu, "memory": mem}},
        }],
        "terminationGracePeriodSeconds": 0,
    }
    if affinity:
        spec["affinity"] = affinity
    if tolerations:
        spec["tolerations"] = tolerations
    return {"apiVersion": "v1", "kind": "Pod",
            "metadata": {"name": name, "namespace": ns, "labels": labels},
            "spec": spec}


def node_affinity(profile):
    return {"nodeAffinity": {"requiredDuringSchedulingIgnoredDuringExecution": {
        "nodeSelectorTerms": [{"matchExpressions": [
            {"key": k, "operator": "In", "values": [v]}
            for k, v in sorted(profile.items())]}]}}}


def tol(pool):
    return [{"key": "pool", "operator": "Equal", "value": pool,
             "effect": "NoSchedule"}]


def profile_from_node(node_labels, keys, rng, k):
    chosen = rng.sample(keys, k) if k else []
    return {key: node_labels[key] for key in chosen}


# ---------------------------------------------------------------- controls --
TIERS = {NS_V: "established", NS_B: "self-service", NS_A: "self-service"}


def setup_namespaces():
    # Two tenant classes, the usual way operators deploy label restrictions:
    # established tenants (the victims) keep fine-grained placement; self-service
    # tenants (background tenants and the attacker) are subject to C1/C3.
    for ns in TENANT_NAMESPACES:
        kubectl(["create", "namespace", ns])
        kubectl(["label", "namespace", ns, "tenant=true",
                 f"tier={TIERS[ns]}", "--overwrite"])


def apply_c1():
    quota = {
        "apiVersion": "v1", "kind": "ResourceQuota",
        "metadata": {"name": QUOTA_NAME, "namespace": NS_A},
        "spec": {"hard": {"pods": "0"},
                 "scopeSelector": {"matchExpressions": [
                     {"scopeName": "CrossNamespacePodAffinity",
                      "operator": "Exists"}]}},
    }
    apply_list([quota], verb="apply")
    # Admission needs the quota controller to publish status first.
    for _ in range(60):
        r = kubectl(["get", "resourcequota", QUOTA_NAME, "-n", NS_A,
                     "-o", "jsonpath={.status.hard.pods}"])
        if r.stdout.strip() == "0":
            return
        time.sleep(1)
    sys.exit("ResourceQuota status never populated (is kube-controller-manager running?)")


def apply_c2(nodes, rng, attacker_pool_frac):
    names = [n["metadata"]["name"] for n in nodes]
    rng.shuffle(names)
    n_att = max(1, int(round(len(names) * attacker_pool_frac)))
    att, shared = names[:n_att], names[n_att:]
    kubectl(["label", "nodes", *att, "pool=attacker", "--overwrite"])
    kubectl(["label", "nodes", *shared, "pool=shared", "--overwrite"])
    kubectl(["taint", "nodes", "-l", "pool=attacker",
             "pool=attacker:NoSchedule", "--overwrite"])
    kubectl(["taint", "nodes", "-l", "pool=shared",
             "pool=shared:NoSchedule", "--overwrite"])
    return set(att), set(shared)


def apply_c3(allowed_keys):
    allowed = "[" + ", ".join(f"'{k}'" for k in allowed_keys) + "]"
    na = "object.spec.affinity.nodeAffinity"
    policy = {
        "apiVersion": "admissionregistration.k8s.io/v1",
        "kind": "ValidatingAdmissionPolicy",
        "metadata": {"name": VAP_NAME},
        "spec": {
            "failurePolicy": "Fail",
            "matchConstraints": {"resourceRules": [{
                "apiGroups": [""], "apiVersions": ["v1"],
                "operations": ["CREATE", "UPDATE"], "resources": ["pods"]}]},
            "validations": [
                {"expression":
                    f"!has(object.spec.nodeSelector) || "
                    f"object.spec.nodeSelector.all(k, k in {allowed})",
                 "message": "nodeSelector uses a node label this tenant may not request"},
                {"expression":
                    f"!has(object.spec.affinity) || !has({na}) || "
                    f"!has({na}.requiredDuringSchedulingIgnoredDuringExecution) || "
                    f"{na}.requiredDuringSchedulingIgnoredDuringExecution"
                    f".nodeSelectorTerms.all(t, !has(t.matchExpressions) || "
                    f"t.matchExpressions.all(e, e.key in {allowed}))",
                 "message": "required node affinity uses a node label this tenant may not request"},
                {"expression":
                    f"!has(object.spec.affinity) || !has({na}) || "
                    f"!has({na}.preferredDuringSchedulingIgnoredDuringExecution) || "
                    f"{na}.preferredDuringSchedulingIgnoredDuringExecution"
                    f".all(p, !has(p.preference.matchExpressions) || "
                    f"p.preference.matchExpressions.all(e, e.key in {allowed}))",
                 "message": "preferred node affinity uses a node label this tenant may not request"},
            ],
        },
    }
    binding = {
        "apiVersion": "admissionregistration.k8s.io/v1",
        "kind": "ValidatingAdmissionPolicyBinding",
        "metadata": {"name": VAP_NAME + "-binding"},
        "spec": {"policyName": VAP_NAME, "validationActions": ["Deny"],
                 "matchResources": {"namespaceSelector": {
                     "matchLabels": {"tier": "self-service"}}}},
    }
    apply_list([policy, binding], verb="apply")
    time.sleep(3)  # let the policy reach the API server's admission chain


def cleanup():
    for ns in TENANT_NAMESPACES:
        kubectl(["delete", "namespace", ns, "--wait=true", "--timeout=180s"])
    kubectl(["delete", "validatingadmissionpolicybinding",
             VAP_NAME + "-binding", "--ignore-not-found"])
    kubectl(["delete", "validatingadmissionpolicy", VAP_NAME,
             "--ignore-not-found"])
    kubectl(["taint", "nodes", "-l", "type=kwok", "pool-"])
    kubectl(["label", "nodes", "-l", "type=kwok", "pool-"])


# ------------------------------------------------------------------- waits --
def settled(pods):
    for p in pods:
        if p["spec"].get("nodeName"):
            continue
        conds = p.get("status", {}).get("conditions", [])
        if any(c["type"] == "PodScheduled" and c["status"] == "False"
               and c.get("reason") == "Unschedulable" for c in conds):
            continue
        return False
    return True


def wait_settled(namespaces, run_id, timeout=300):
    t0 = time.time()
    while time.time() - t0 < timeout:
        pods = []
        for ns in namespaces:
            pods += kjson(["get", "pods", "-n", ns,
                           "-l", f"exp={run_id}"])["items"]
        if settled(pods):
            return pods
        time.sleep(2)
    print("warning: timeout waiting for scheduling to settle", file=sys.stderr)
    return pods


# ----------------------------------------------------------------- metrics --
def wilson(k, n, z=1.96):
    if n == 0:
        return (float("nan"), float("nan"))
    p = k / n
    d = 1 + z * z / n
    c = (p + z * z / (2 * n)) / d
    h = z * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n)) / d
    return (max(0.0, c - h), min(1.0, c + h))


def sched_latency_s(p):
    created = p["metadata"]["creationTimestamp"]
    for c in p.get("status", {}).get("conditions", []):
        if c["type"] == "PodScheduled" and c["status"] == "True":
            f = "%Y-%m-%dT%H:%M:%SZ"
            return (datetime.strptime(c["lastTransitionTime"], f)
                    - datetime.strptime(created, f)).total_seconds()
    return None


# -------------------------------------------------------------------- main --
def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--condition", choices=["C0", "C1", "C2", "C3"], required=True)
    ap.add_argument("--mode", choices=["node", "node-adaptive", "pod"],
                    default="node",
                    help="node-adaptive: like node, but the attacker drops any "
                         "label key the C3 policy forbids instead of being rejected")
    ap.add_argument("--seed", type=int, default=1)
    ap.add_argument("--victims", type=int, default=50)
    ap.add_argument("--background", type=int, default=300)
    ap.add_argument("--attackers-per-victim", type=int, default=5)
    ap.add_argument("--affinity-features", type=int, default=2,
                    help="number of node-label keys each victim requires")
    ap.add_argument("--attacker-pool-frac", type=float, default=0.2,
                    help="C2: share of nodes in the attacker tenant's pool")
    ap.add_argument("--c3-allowed-keys", default="hw.mem",
                    help="C3: comma-separated node-label keys tenants may request")
    ap.add_argument("--out", default="results.csv")
    ap.add_argument("--keep", action="store_true", help="do not clean up")
    a = ap.parse_args()

    rng = random.Random(a.seed)
    run_id = f"{a.condition}-{a.mode}-s{a.seed}-{int(time.time())}"
    nodes = assert_simulated_cluster()
    label_keys = sorted(k for k in nodes[0]["metadata"]["labels"]
                        if k.startswith("hw."))
    node_labels = {n["metadata"]["name"]: n["metadata"]["labels"] for n in nodes}

    cleanup()                       # start from a clean state
    setup_namespaces()

    # ---- control for this condition (in place before any tenant pod) ----
    shared_nodes = set(node_labels)
    if a.condition == "C1":
        apply_c1()
    elif a.condition == "C2":
        _, shared_nodes = apply_c2(nodes, rng, a.attacker_pool_frac)
    elif a.condition == "C3":
        apply_c3([k.strip() for k in a.c3_allowed_keys.split(",") if k.strip()])
    legit_tol = tol("shared") if a.condition == "C2" else None
    att_tol = tol("attacker") if a.condition == "C2" else None

    # ---- victims and background tenants ----
    victims, victim_profiles, background = [], {}, []
    node_names = sorted(node_labels)
    for i in range(a.victims):
        src = node_labels[rng.choice(node_names)]
        prof = profile_from_node(src, label_keys, rng, a.affinity_features)
        victim_profiles[i] = prof
        victims.append(pod(f"victim-{i}", NS_V,
                           {"exp": run_id, "role": "victim", "vid": str(i)},
                           f"{rng.randint(1, 4)}", f"{rng.randint(1, 8)}Gi",
                           node_affinity(prof) if prof else None, legit_tol))
    for j in range(a.background):
        src = node_labels[rng.choice(node_names)]
        k = rng.randint(0, a.affinity_features)
        prof = profile_from_node(src, label_keys, rng, k)
        background.append(pod(f"bg-{j}", NS_B,
                              {"exp": run_id, "role": "background"},
                              f"{rng.randint(1, 4)}", f"{rng.randint(1, 8)}Gi",
                              node_affinity(prof) if prof else None, legit_tol))
    apply_list(victims + background)
    legit_pods = wait_settled([NS_V, NS_B], run_id)

    # ---- attacker ----
    attackers = []
    allowed = set(label_keys)
    if a.mode == "node-adaptive" and a.condition == "C3":
        allowed = {k.strip() for k in a.c3_allowed_keys.split(",") if k.strip()}
    for i, prof in victim_profiles.items():
        aprof = {k: v for k, v in prof.items() if k in allowed}
        for r in range(a.attackers_per_victim):
            labels = {"exp": run_id, "role": "attacker", "target": str(i),
                      "spread": f"a{i}"}
            if a.mode in ("node", "node-adaptive"):
                aff = node_affinity(aprof) if aprof else {}
                aff["podAntiAffinity"] = {
                    "requiredDuringSchedulingIgnoredDuringExecution": [{
                        "labelSelector": {"matchLabels": {"spread": f"a{i}"}},
                        "topologyKey": "kubernetes.io/hostname"}]}
            else:
                aff = {"podAffinity": {
                    "requiredDuringSchedulingIgnoredDuringExecution": [{
                        "labelSelector": {"matchLabels": {"vid": str(i)}},
                        "namespaces": [NS_V],
                        "topologyKey": "kubernetes.io/hostname"}]}}
            attackers.append(pod(f"att-{i}-{r}", NS_A, labels, "10m", "16Mi",
                                 aff, att_tol))
    apply_list(attackers)
    att_pods = wait_settled([NS_A], run_id)

    # ---- measure ----
    v_by_id = {int(p["metadata"]["labels"]["vid"]): p for p in legit_pods
               if p["metadata"]["labels"].get("role") == "victim"}
    bg = [p for p in legit_pods if p["metadata"]["labels"].get("role") == "background"]
    att_node = {}
    for p in att_pods:
        n = p["spec"].get("nodeName")
        if n:
            att_node.setdefault(int(p["metadata"]["labels"]["target"]), set()).add(n)

    sched_victims = {i: p["spec"]["nodeName"] for i, p in v_by_id.items()
                     if p["spec"].get("nodeName")}
    colocated = sum(1 for i, n in sched_victims.items()
                    if n in att_node.get(i, set()))
    lo, hi = wilson(colocated, len(sched_victims))

    legit_intended = a.victims + a.background
    legit_admitted = len(v_by_id) + len(bg)
    legit_sched = sum(1 for p in list(v_by_id.values()) + bg if p["spec"].get("nodeName"))
    att_intended = len(attackers)
    att_admitted = len(att_pods)
    att_sched = sum(1 for p in att_pods if p["spec"].get("nodeName"))

    lat = [x for x in (sched_latency_s(p) for p in list(v_by_id.values()) + bg)
           if x is not None]
    per_node = {n: 0 for n in node_labels}
    for p in list(v_by_id.values()) + bg + att_pods:
        if p["spec"].get("nodeName"):
            per_node[p["spec"]["nodeName"]] += 1
    counts = list(per_node.values())
    mean = sum(counts) / len(counts)
    sd = math.sqrt(sum((c - mean) ** 2 for c in counts) / len(counts))

    row = {
        "run_id": run_id, "condition": a.condition, "mode": a.mode,
        "seed": a.seed, "nodes": len(nodes), "victims": a.victims,
        "background": a.background,
        "attackers_per_victim": a.attackers_per_victim,
        "affinity_features": a.affinity_features,
        "victims_scheduled": len(sched_victims),
        "victims_colocated": colocated,
        "colocation_rate": round(colocated / len(sched_victims), 4) if sched_victims else "",
        "colocation_ci95_lo": round(lo, 4), "colocation_ci95_hi": round(hi, 4),
        "legit_rejected_frac": round(1 - legit_admitted / legit_intended, 4),
        "legit_unschedulable_frac": round(1 - legit_sched / legit_admitted, 4) if legit_admitted else "",
        "attacker_rejected_frac": round(1 - att_admitted / att_intended, 4) if att_intended else "",
        "attacker_unschedulable_frac": round(1 - att_sched / att_admitted, 4) if att_admitted else "",
        "legit_sched_latency_mean_s": round(sum(lat) / len(lat), 3) if lat else "",
        "node_packing_cv": round(sd / mean, 4) if mean else "",
    }
    new = not os.path.exists(a.out)
    with open(a.out, "a", newline="") as f:
        w = csv.DictWriter(f, fieldnames=list(row))
        if new:
            w.writeheader()
        w.writerow(row)
    print(json.dumps(row, indent=2))

    if not a.keep:
        cleanup()


if __name__ == "__main__":
    main()
