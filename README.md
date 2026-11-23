# Measuring Kubernetes-Native Controls Against Scheduler-Guided Co-Location Attacks — Reproducibility Artifact

This repository is the artifact for the paper *"Measuring the Effectiveness of
Kubernetes-Native Controls Against Scheduler-Guided Co-Location Attacks"*
(N. Patel, M. Raj, School of Engineering, P P Savani University).

It runs the experiments on the **real Kubernetes scheduler** (`kube-scheduler`
v1.30.2) with simulated nodes (KWOK), measures four Kubernetes-native controls
against two attacker strategies, and reproduces every number and figure in the
paper. All results in the paper were produced by these scripts; nothing is
hand-entered.

## What is measured

- **Co-location rate** for each control (C0 baseline, C1 cross-namespace
  pod-affinity quota, C2 per-tenant node pools, C3 node-label admission policy)
  against a node-affinity attacker and a cross-namespace pod-affinity attacker.
- **Cost to legitimate tenants** of each control (pods rejected, pods left
  unschedulable, node-packing CV).
- **The reconnaissance channel**: how much a low-privilege tenant learns about
  node labels and taints from scheduler messages.

## Contents

| Path | What it is |
|------|------------|
| `PROTOCOL.md` | Step-by-step setup and run instructions |
| `make_nodes.py` | Create N simulated nodes with random hardware labels |
| `run_experiment.py` | One experiment run: build workloads, apply a control, measure |
| `recon_probe.py` | Reconnaissance-channel measurement |
| `summarize.py` | Pool raw runs into the paper's tables |
| `run_all.sh` | Run the full matrix (4 controls × 2 attackers × 5 seeds × 2 sizes) |
| `controls/` | Reference C1 and C3 control manifests |
| `results.csv` | Raw per-run results (60 runs) |
| `summary.csv` | Pooled results used in the paper's tables |
| `recon.csv`, `recon_taints.csv` | Reconnaissance results |

## Requirements

A Linux machine (or WSL2 / macOS), and three tools: `kubectl`, `kwokctl`,
`kwok`. See `PROTOCOL.md` for install commands.

## Quick start

```bash
kwokctl create cluster --name coloc \
  --kube-apiserver-arg='--enable-admission-plugins=PodNodeSelector,PodTolerationRestriction'
kubectl config use-context kwok-coloc
./run_all.sh            # writes results.csv, recon.csv
python3 summarize.py results.csv summary.csv
```

## Safety

The scripts refuse to run against anything but a private, simulated KWOK
cluster. All experiments must be run on a cluster you own, consistent with the
ethics guidance of the co-location literature.

## License

