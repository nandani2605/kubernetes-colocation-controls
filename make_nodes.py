#!/usr/bin/env python3
"""
Create simulated (KWOK) Kubernetes nodes with random hardware labels.

The real kube-scheduler places pods onto these nodes exactly as it would onto
real nodes: it reads each node's declared labels, taints and allocatable
capacity. No kubelet runs, so this is cheap enough to create hundreds of nodes
on one laptop. Placement (pod.spec.nodeName) is the ground truth for
co-location, as Section X of the paper proposes.

Usage:
    python3 make_nodes.py --nodes 100 --seed 1
    python3 make_nodes.py --nodes 100 --seed 1 --delete   # remove them
"""
import argparse
import json
import random
import subprocess
import sys

# Heterogeneity model, following REPTTACK [13]: a few label keys, each with a
# few values. More keys/values => a more "heterogeneous" cluster.
LABEL_SPACE = {
    "hw.cpu": ["skylake", "cascadelake", "zen3", "zen4"],
    "hw.gpu": ["none", "t4", "a100"],
    "hw.disk": ["hdd", "ssd", "nvme"],
    "hw.mem": ["low", "med", "high"],
}

NODE_PREFIX = "kwok-node-"


def node_manifest(name, labels):
    return {
        "apiVersion": "v1",
        "kind": "Node",
        "metadata": {
            "name": name,
            "annotations": {"kwok.x-k8s.io/node": "fake"},
            "labels": {
                "kubernetes.io/hostname": name,
                "kubernetes.io/os": "linux",
                "type": "kwok",
                **labels,
            },
        },
        "spec": {
            # KWOK's default "fake" taint keeps ordinary pods off these nodes
            # unless they tolerate it. We remove it so the scheduler treats the
            # nodes as normal; per-tenant taints are added later for C2.
            "taints": []
        },
        "status": {
            "allocatable": {"cpu": "32", "memory": "256Gi", "pods": "110"},
            "capacity": {"cpu": "32", "memory": "256Gi", "pods": "110"},
            "nodeInfo": {
                "kubeletVersion": "fake", "kubeProxyVersion": "fake",
                "machineID": "", "systemUUID": "", "bootID": "",
                "kernelVersion": "fake", "osImage": "fake",
                "containerRuntimeVersion": "fake",
                "operatingSystem": "linux", "architecture": "amd64",
            },
            "phase": "Running",
        },
    }


def kubectl(args, stdin=None):
    r = subprocess.run(["kubectl", *args], input=stdin, text=True,
                       capture_output=True)
    if r.returncode != 0:
        sys.stderr.write(r.stderr)
    return r


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--nodes", type=int, default=100)
    ap.add_argument("--seed", type=int, default=1)
    ap.add_argument("--delete", action="store_true")
    a = ap.parse_args()

    if a.delete:
        kubectl(["delete", "nodes", "-l", "type=kwok", "--wait=false"])
        print("deleted kwok nodes")
        return

    rng = random.Random(a.seed)
    items = []
    for i in range(a.nodes):
        labels = {k: rng.choice(v) for k, v in LABEL_SPACE.items()}
        items.append(node_manifest(f"{NODE_PREFIX}{i:04d}", labels))

    doc = json.dumps({"apiVersion": "v1", "kind": "List", "items": items})
    r = kubectl(["apply", "-f", "-"], stdin=doc)
    if r.returncode == 0:
        print(f"created/updated {a.nodes} kwok nodes (seed={a.seed})")


if __name__ == "__main__":
    main()
