# Measuring the Effectiveness of Kubernetes-Native Controls Against Scheduler-Guided Co-Location Attacks

**Abstract —** In a shared cloud, a tenant that wants to attack another tenant's workload through shared hardware must first run on the same physical server: it must achieve co-location. On Kubernetes, a tenant can steer placement by copying the victim's scheduling requests, so co-location is not only a brute-force problem but a scheduler problem. Prior work shows the attack but not whether the controls Kubernetes already ships with stop it; the attack studies and the defense studies are separate, and the Kubernetes-native controls have never been tested against the attack. We close that gap experimentally. We build a testbed on the real Kubernetes scheduler (v1.30.2) with simulated nodes, implement two attacker strategies (copying node affinity, and cross-namespace pod affinity to the victim's pods), and measure four native controls against them: a cross-namespace pod-affinity quota, per-tenant node pools, a node-label admission policy, and the default scheduler as baseline. Each control is scored by the co-location rate it allows and the cost it imposes on legitimate tenants, over five seeds with 95% confidence intervals. We find that no single native control stops both strategies: the cross-namespace quota eliminates the pod-affinity attack (100% → 0%) but leaves node-affinity copying unchanged (49.6% → 52.8%); the label policy does the reverse and additionally rejects 50% of legitimate pods; only per-tenant pools stop both, at the cost of leaving 60–100% of attacker pods unschedulable. We also show that the node-affinity attack weakens with cluster size (49.6% at 100 nodes to 8.0% at 500) while the pod-affinity attack does not, and we give the first measurement of the reconnaissance channel: a low-privilege tenant recovers the full node-label map and every taint name from scheduler messages, and restricting event access does not close it because the same text is on the tenant's own pod status. We release the testbed as a reproducibility artifact.

**Keywords —** co-location attack, co-residency, Kubernetes, multi-tenancy, scheduler security, admission control, node affinity, container orchestration.

## I. Introduction

Cloud providers run many tenants on the same physical servers. This sharing lowers cost but creates a risk: two tenants on one server share hardware such as the processor cache or the memory bus, and a large body of work shows attacks that use this sharing — cache side channels [1], [2], memory-bus covert channels [3], cross-tenant attacks in PaaS clouds [4], cache attacks on modern public clouds [5], and performance interference [6]. Every one of these attacks needs co-location first: the attacker's workload must run on the same physical server as the victim. Most research studies what happens after co-location; the step of getting there has had less attention [7].

Containers and Kubernetes changed this step. In Kubernetes a scheduler picks the server, and any tenant that can create pods can attach placement requests — node affinity, pod affinity, tolerations — to steer that choice. Fang et al. showed in REPTTACK that an attacker who copies a victim's placement requests raises co-location to as much as 80% with five instances [13]. On the defense side, Kubernetes ships several controls that could limit such requests, and security-aware scheduling has been proposed [14], but the attack studies and the defense studies are separate. No prior work tests the controls Kubernetes already provides against a scheduler-guided co-location attack, so an operator cannot say which native control to turn on, or what it costs.

This paper answers that question with measurements. We make four contributions:

- **A testbed on the real scheduler.** Unlike simulator-based studies, our attacks run against the actual Kubernetes scheduler and its real admission controls, with simulated nodes so the experiment fits on one machine (Section IV).
- **A head-to-head evaluation of four Kubernetes-native controls** against two attacker strategies, each scored for both security (co-location rate) and cost to legitimate tenants, with confidence intervals (Section V).
- **The finding that no single native control stops both attacker strategies,** and a measurement of the cost each control imposes, including a control that pays its full cost while giving no protection (Section V, VI).
- **The first measurement of the reconnaissance channel** by which a low-privilege tenant learns the node labels and taints the attack relies on, and evidence that restricting event access does not close it (Section V-D).

We release the full testbed and analysis scripts so the results can be reproduced and extended.

## II. Background and Threat Model

### A. Co-location on Kubernetes

Co-location means the attacker's pod and the victim's pod are bound to the same node. The Kubernetes scheduler decides this in two phases [46]: a *filter* phase that removes nodes a pod cannot run on, and a *score* phase that ranks the rest. Placement requests shape both phases. Node selectors and node affinity ask for nodes with certain labels; pod affinity and anti-affinity ask to run near or away from pods with certain labels; taints and tolerations keep pods off nodes unless the pod tolerates the taint. Three facts make these security-relevant: the requests are part of the pod spec, so any tenant that can create pods can write them; namespaces do not decide which node a pod runs on, so pods of different tenants share nodes [51]; and a pod-affinity term that crosses namespaces must set a namespaces field or selector [15].

### B. Threat model

The attacker is an ordinary tenant with a valid account that can create pods in its own namespace. It has no administrator rights, exploits no control-plane bug, and must obey quotas and admission. It may know something about the victim — in particular the victim's placement requests or pod labels — consistent with REPTTACK and the serverless study [13], [7]. The attacker's goal is co-location with a chosen victim; what happens after co-location is out of scope. We evaluate two strategies a tenant can actually express in Kubernetes:

- **Node-affinity copying (`node`).** The attacker copies the victim's required node affinity, requests minimal resources, and spreads its own replicas across nodes with pod anti-affinity, exactly as REPTTACK describes [13].
- **Cross-namespace pod affinity (`pod`).** The attacker requires pod affinity to the victim's pods across namespaces, naming the victim's namespace and pod labels. This targets the victim directly rather than the nodes the victim prefers.

## III. Related Work

**Co-location on VMs.** Ristenpart et al. first showed placement-based co-residency on EC2 [10]; Xu et al. [11] and Varadarajan et al. [12] later measured how provider policy changes the cost. These use brute force and launch timing, not a tenant-controllable scheduler.

**Scheduler-guided attacks.** REPTTACK copies a victim's affinity on filter-then-score schedulers and reaches up to 80% co-location with five instances [13]; HeteroScore links cluster heterogeneity to co-location success and proposes label hiding [20], [26]; PodBeater exploits multi-value affinity in Kubernetes [36]; on serverless, Shao et al. learn scheduler features and reach co-location on Azure Functions [7]. These establish the attack. They are evaluated on simulators and small clusters, and — except PodBeater — come from one research group; none tests the Kubernetes-native controls as defenses.

**Defenses.** Rossi et al. enforce cluster-level scheduling policy with OPA Gatekeeper and measure correctness and overhead, but not against an attack [14]; Kubernetes documents a cross-namespace pod-affinity quota scope [15] and admission controllers for selectors and tolerations [54]; sandboxes isolate workloads on a shared node but do not prevent co-location [69]. The gap this paper fills is that none of these native controls has been measured against the scheduler-guided attack.

## IV. Method and Testbed

### A. Testbed

We run the unmodified Kubernetes control plane — etcd, API server, controller manager and the real `kube-scheduler` v1.30.2 — under `kwokctl`, with nodes simulated by KWOK. The scheduler makes placement decisions from each node's declared labels, taints and allocatable capacity, so a simulated node yields the same decision as a real one; KWOK runs no kubelet, so hundreds of nodes fit on one machine. This matches the approach Rossi et al. used to reach 1,000 nodes [14], [70]. Placement — `pod.spec.nodeName` — is the ground truth for co-location, so no side-channel test is needed, as the attack's own designers note for an owned cluster [13]. The API server runs with the `PodNodeSelector` and `PodTolerationRestriction` admission plugins enabled.

### B. Workload and heterogeneity

Following REPTTACK's heterogeneity model [13], each node carries four label keys (processor, accelerator, disk, memory class), each with three or four values, assigned at random. Each run creates 50 victim tenants, 300 background tenants, and, per victim, 5 attacker pods. Victims and background tenants issue required node affinity over a random subset of the label keys; the attacker copies the targeted victim's requests. We run at 100 and 500 nodes, five random seeds each.

### C. Conditions

The baseline and three Kubernetes-native controls (Table I) are each applied before any tenant pod is created.

**TABLE I. EXPERIMENTAL CONDITIONS**

| ID | Control | What it is |
|----|---------|------------|
| C0 | none | Default scheduler, baseline |
| C1 | Cross-namespace pod-affinity quota | A ResourceQuota with the `CrossNamespacePodAffinity` scope, limit 0, in the attacker namespace [15] |
| C2 | Per-tenant node pools | Disjoint, tainted node pools for the established tenants and the self-service tenants (the separation `PodTolerationRestriction` enforces) [54] |
| C3 | Node-label admission policy | A `ValidatingAdmissionPolicy` (built-in, CEL) that limits which node-label keys a self-service namespace may request |

### D. Metrics

The security metric is the **co-location rate**: the fraction of scheduled victims for which at least one of the victim's attacker pods is bound to the victim's node. We report it with a Wilson 95% confidence interval over the pooled victims of five seeds. The cost metrics, all borne by legitimate tenants, are: the fraction of legitimate pods *rejected* at admission, the fraction left *unschedulable*, the fraction of *attacker* pods rejected or unschedulable, and the node-packing coefficient of variation (CV). Scheduling latency is not reported: with no kubelet, KWOK binds pods near-instantly, so latency is not a meaningful cost signal on this testbed and would need a real-kubelet cluster.

### E. Reconnaissance measurement

Both attack strategies assume the attacker knows the victim's requests or labels. We measure how much a tenant can learn with only ordinary permissions. A probe is a pod that requests an impossible amount of CPU, so it is never placed and consumes nothing, but the scheduler still explains why no node fits — naming untolerated taints verbatim, and, for a probe that also requires a given label, reporting how many nodes passed the label filter before failing on CPU. That count leaks the label distribution. We score the recovered label map and taint set against ground truth, and compare a tenant that can read events with one whose RBAC cannot.

## V. Results

### A. Baseline and the node-affinity attack

**TABLE II. CO-LOCATION RATE AND COST, 100 NODES, node-affinity attacker (mean of 5 seeds; 95% CI on the rate)**

| Cond. | Co-loc. rate | 95% CI | L-rej | A-rej | A-uns | CV |
|-------|--------------|--------|-------|-------|-------|-----|
| C0 | 0.496 | [0.435, 0.558] | 0.00 | 0.00 | 0.01 | 0.42 |
| C1 | 0.528 | [0.466, 0.589] | 0.00 | 0.00 | 0.01 | 0.41 |
| C2 | 0.000 | [0.000, 0.015] | 0.00 | 0.00 | 0.60 | 0.30 |
| C3 | 0.000 | [0.000, 0.015] | 0.50 | 1.00 | — | 0.37 |

*L-rej: fraction of legitimate pods rejected at admission. A-rej / A-uns: fraction of attacker pods rejected / left unschedulable. CV: node-packing coefficient of variation. Legitimate pods were never left unschedulable in any node-mode condition, so that column is omitted.*

The baseline node-affinity attack reaches 49.6% co-location, in the range REPTTACK reports. The cross-namespace quota (C1) leaves it essentially unchanged (52.8%, confidence intervals overlapping C0): the quota governs cross-namespace *pod* affinity and does not touch node-affinity copying. The per-tenant pools (C2) and the label policy (C3) both drive it to zero, but at a cost — C2 leaves 60% of attacker pods unschedulable, and C3 rejects half of the legitimate self-service pods along with every attacker pod, because legitimate tenants use the same node labels the policy forbids.

### B. The pod-affinity attack

**TABLE III. CO-LOCATION RATE AND COST, 100 NODES, pod-affinity attacker** (columns as in Table II)

| Cond. | Co-loc. rate | 95% CI | L-rej | A-rej | A-uns | CV |
|-------|--------------|--------|-------|-------|-------|-----|
| C0 | 1.000 | [0.985, 1.000] | 0.00 | 0.00 | 0.00 | 0.44 |
| C1 | 0.000 | [0.000, 0.015] | 0.00 | 1.00 | — | 0.24 |
| C2 | 0.000 | [0.000, 0.015] | 0.00 | 0.00 | 1.00 | 0.56 |
| C3 | 1.000 | [0.985, 1.000] | 0.50 | 0.00 | 0.00 | 0.61 |

The cross-namespace pod-affinity attack is far stronger at baseline — 100% co-location — because it targets the victim's pods directly rather than the nodes the victim prefers. Here the quota (C1) is decisive: it rejects every attacker pod and drives co-location to zero. But the label policy (C3) is useless against this strategy: it restricts node labels, which this attacker does not use, so co-location stays at 100% while the policy still rejects half the legitimate pods — the full cost for no protection.

### C. Effect of cluster size

**TABLE IV. BASELINE (C0) CO-LOCATION RATE BY CLUSTER SIZE**

| Attacker | 100 nodes | 500 nodes |
|----------|-----------|-----------|
| node | 0.496 [0.435, 0.558] | 0.080 [0.052, 0.120] |
| pod | 1.000 [0.985, 1.000] | 1.000 [0.985, 1.000] |

The node-affinity attack weakens sharply as the cluster grows — from 49.6% at 100 nodes to 8.0% at 500 — because the victim's affinity profile matches more candidate nodes and the attacker's copies spread among them. The pod-affinity attack does not weaken at all: it names the victim's pods, so it converges on the victim's node regardless of cluster size. Per-tenant pools (C2) hold co-location at zero at both sizes.

### D. The reconnaissance channel

**TABLE V. WHAT A TENANT RECOVERS FROM SCHEDULER MESSAGES (100 nodes)**

| Target | Recovered | Probes |
|--------|-----------|--------|
| Node-label key/value pairs | 13 / 13 (100%) | 91 |
| Exact per-label node counts | 9 / 13 | (same) |
| Untolerated taint names | 2 / 2 | 1 |

A tenant with ordinary permissions recovered the entire node-label map — every key and value — and both taint names, using cheap probe pods that are never scheduled and consume no resources. Restricting the tenant's RBAC so it cannot read events does **not** close the channel: the identical scheduler explanation is written to the tenant's own pod status, which it can always read. In a direct test, a service account with only pod-read permission still retrieved the full message (`"0/100 nodes are available: 100 Insufficient cpu..."`) while event access was forbidden. The information both attack strategies assume is therefore available to any tenant at low cost, and the obvious mitigation — hiding events — is ineffective.

## VI. Discussion

**No single native control is sufficient.** The two strategies have disjoint weaknesses. C1 stops the pod-affinity attack because that attack is expressed as cross-namespace pod affinity, exactly what the quota scope governs; it does nothing against node-affinity copying. C3 stops node-affinity copying because that attack is expressed through node labels, exactly what the policy restricts; it does nothing against the pod-affinity attack. An operator who deploys either control alone is protected against one strategy and fully exposed to the other. Only C2, which physically separates the tenants onto disjoint node pools, stops both — and it is the most expensive, leaving most attacker pods (and, in a tighter cluster, legitimate pods) unschedulable and lowering node packing.

**Cost can be paid for nothing.** The C3/pod cell is the clearest warning: the label policy rejects half the legitimate pods and leaves the attack at 100%. A control chosen without knowing the attacker's strategy can impose its full cost and deliver no security.

**Scale is a partial, uneven defense.** The node-affinity attack decays with cluster size, consistent with HeteroScore's simulator result [20]; the pod-affinity attack does not. Growth is therefore not a general mitigation — it helps against the weaker strategy and not the stronger one.

**Reconnaissance is cheap and hard to suppress.** The attack's knowledge assumption holds in practice: the label map and taints leak through scheduler messages, and the natural mitigation of hiding events fails because pod status carries the same text. Suppressing this channel would require changing what the scheduler reports, not just who can read events.

The practical implication is that defending a shared Kubernetes cluster against co-location requires combining controls — a cross-namespace affinity quota *and* label restriction, or tenant pools where the cost is acceptable — and that the choice must be driven by which placement primitives tenants are allowed to use, not by a single default.

## VII. Limitations

The nodes are simulated: placement logic is the real scheduler, but no real workloads run, so we do not measure runtime interference or scheduling latency, and resource-pressure effects on packing are modeled through declared capacity only. Results are from one scheduler version (v1.30.2) with default plugins on a single machine; a production scheduler may use scoring that samples nodes in very large clusters, which can change the size trend. The heterogeneity model and workload mix follow REPTTACK for comparability, and co-location success depends on how many affinity features victims use, which we fix as a variable. Confirming the trends on a real multi-node cluster (for example CloudLab [62]), and over more scheduler versions and plugins, is future work.

## VIII. Conclusion

Shared-hardware attacks need co-location first, and on Kubernetes a tenant can steer co-location through the scheduler. Prior work showed the attack but never tested the controls Kubernetes already provides against it. We built a testbed on the real scheduler and measured four native controls against two attacker strategies. No single native control stops both: the cross-namespace quota stops only the pod-affinity attack, the label policy stops only node-affinity copying and rejects half the legitimate pods, and only physical pool separation stops both, at the highest cost — while one configuration pays the full cost for no protection at all. The node-affinity attack weakens with cluster size and the pod-affinity attack does not, and the reconnaissance the attacks rely on is cheap and resists the obvious mitigation. Defending a shared cluster therefore means combining controls chosen for the placement primitives tenants may use. We release the testbed so these results can be reproduced and extended to real clusters.
