# Experiment protocol: turning the co-location review into a research paper

This package runs the test plan in Section X of the paper for real, on an
actual Kubernetes scheduler and real Kubernetes admission controls, using
**simulated nodes** so it fits on one laptop. Every number the research paper
needs comes out of `results.csv` and `recon.csv`.

Why simulated nodes are valid: the Kubernetes scheduler decides placement from
each node's declared labels, taints and allocatable capacity. It never touches
the physical machine. So a simulated node produces the same placement decision
as a real one, and the node each pod lands on (`pod.spec.nodeName`) is the
ground truth for co-location. This is the same approach Rossi et al. used to
reach 1,000 nodes, which the paper already cites.

Run this only on a cluster you own. The scripts refuse to start unless every
node is a simulated (KWOK) node.

---

## 0. What you need

- A Linux machine (or WSL2 on Windows, or macOS). 8 GB RAM is enough for
  100–500 nodes; 16 GB for 1,000.
- About 30 minutes of setup, then the matrix runs unattended.
- Three tools: `kubectl`, `kwokctl`, `kwok`. Install below.

```bash
# kubectl
curl -LO "https://dl.k8s.io/release/$(curl -L -s https://dl.k8s.io/release/stable.txt)/bin/linux/amd64/kubectl"
chmod +x kubectl && sudo mv kubectl /usr/local/bin/

# kwokctl + kwok  (simulated-node control plane; no Docker needed in binary mode)
KWOK=$(curl -s https://api.github.com/repos/kubernetes-sigs/kwok/releases/latest | grep tag_name | cut -d'"' -f4)
for b in kwok kwokctl; do
  curl -LO "https://github.com/kubernetes-sigs/kwok/releases/download/${KWOK}/${b}-linux-amd64"
  chmod +x ${b}-linux-amd64 && sudo mv ${b}-linux-amd64 /usr/local/bin/${b}
done
```

## 1. Create the test cluster

C2 and parts of C1 need two admission plugins turned on, so create the cluster
with them enabled. `kwokctl` builds a full control plane (etcd, API server,
scheduler, controller-manager) with no kubelet.

```bash
kwokctl create cluster --name coloc \
  --kube-apiserver-arg='--enable-admission-plugins=PodNodeSelector,PodTolerationRestriction'
kubectl config use-context kwok-coloc
kubectl get ns    # should respond
```

Everything after this is driven by the Python scripts in this folder.

## 2. Run the whole matrix

```bash
./run_all.sh
```

That runs, for cluster sizes 100 and 500 nodes:

- **4 conditions** (C0 baseline, C1 cross-namespace-affinity quota,
  C2 per-tenant node pools, C3 label-restriction admission policy)
- **2 attacker modes** (`node` = copy the victim's node affinity;
  `pod` = cross-namespace pod affinity to the victim's pods)
- **5 seeds** each, so every number has a mean and a 95% confidence interval.

Then it runs the reconnaissance measurement twice: once as admin, once as a
tenant whose RBAC cannot read events.

To add 1,000-node runs (closer to the paper's larger-cluster claim), set
`SIZES="100 500 1000"` before running. To change how many node-label keys each
victim pins, set `FEATURES`.

Outputs, all written in this folder:

- `results.csv` — one row per run: co-location rate with CI, plus the four cost
  measures (legitimate pods rejected, legitimate pods left unschedulable,
  attacker pods rejected, scheduling latency, node-packing CV).
- `recon.csv` — how many node-label key/value pairs and taints a tenant
  recovered from scheduler messages, admin vs. events-restricted.
- `recon_messages.log` — the raw scheduler explanations, for one quoted example
  in the paper.

## 3. What each script is

| File | Role |
|---|---|
| `make_nodes.py` | Creates N simulated nodes with random hardware labels (the heterogeneity model from REPTTACK). |
| `run_experiment.py` | One run: builds victims, background tenants and the attacker, applies the condition's control, waits for scheduling to settle, and computes co-location rate and costs. The core of the paper's Results. |
| `recon_probe.py` | Measures the reconnaissance channel (Gap 2): what a tenant learns about node labels and taints from "FailedScheduling" messages, and whether removing events access closes it. |
| `run_all.sh` | Runs the full matrix and the reconnaissance measurement. |
| `controls/` | Reference copies of the C1 quota and C3 policy, if you want to inspect or apply them by hand. |

## 4. The results tables to fill in

These are the tables the research paper needs. Fill them from `results.csv`
(average the 5 seeds per cell; put the mean, and the CI for the co-location
rate). Co-location rate is the security measure; the rest are the cost to
legitimate tenants.

**Table A — Node-affinity attacker (mode = node), 100 nodes**

| Condition | Co-location rate (95% CI) | Legit unschedulable | Attacker rejected | Sched. latency (s) | Node-packing CV |
|---|---|---|---|---|---|
| C0 baseline | | | | | |
| C1 cross-ns quota | | | | | |
| C2 per-tenant pools | | | | | |
| C3 label restriction | | | | | |

**Table B — Pod-affinity attacker (mode = pod), 100 nodes** — same columns.
This is where C1 should bite, because C1 only limits cross-namespace *pod*
affinity.

**Table C — Effect of cluster size** — C0 co-location rate at 100 / 500 / 1,000
nodes, to test whether larger clusters are harder (the paper's Gap 3).

**Table D — Reconnaissance channel (from `recon.csv`)**

| Tenant | Label pairs recovered / total (recall) | Node counts exact | Taints recovered | Probe pods used |
|---|---|---|---|---|
| Admin (events readable) | | | | |
| Restricted (no events) | | | | |

## 5. What each result is expected to show

These are the paper's hypotheses (H1–H3 in Section X) stated as predictions.
Your data confirm or refute them — either way it is a finding.

- **H1:** The cross-namespace quota (C1) lowers co-location for the *pod*-mode
  attacker (Table B) but **not** the *node*-mode attacker (Table A). This is
  the paper's central nuance: the control the documentation names as the
  defense does not touch the node-affinity attack.
- **H2:** Per-tenant pools (C2) drive co-location toward zero, at the highest
  cost — the most attacker pods left unschedulable and the lowest node packing.
- **H3:** The label-restriction policy (C3) lowers co-location for the
  node-mode attacker, at the cost of some rejected legitimate pods.
- **Reconnaissance (Table D):** a tenant recovers most of the cluster's label
  map and all untolerated taint names from scheduler messages alone; removing
  events access does **not** close the channel, because the same text is on the
  tenant's own pod status. That is a measured result for Gap 2, which no prior
  study reports.

## 6. From results to the research paper

Once `results.csv` and `recon.csv` exist, send them back and the paper gets
restructured from a review into a research paper:

- **Title:** *Measuring the Effectiveness of Kubernetes-Native Controls
  Against Scheduler-Guided Co-Location Attacks.*
- **Sections III–VIII** (the current literature review and control map) shrink
  into a single **Related Work** section.
- New **Threat Model**, **Testbed and Method** (this protocol), **Results**
  (Tables A–D with the real numbers and the CIs), and **Discussion** sections.
- The contribution changes from "we map the gap" to "we measured it": first
  experimental numbers for Kubernetes-native controls against this attack, and
  the first measurement of the reconnaissance channel.
- This package ships with the paper as the reproducibility artifact, which many
  venues now reward.

The honesty line still holds: every number in the paper must come from a run on
your machine. Nothing here is fabricated, and nothing is filled in until your
CSVs come back.
