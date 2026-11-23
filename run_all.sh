#!/usr/bin/env bash
# Full experiment matrix for the paper. Run on a private KWOK test cluster.
#   4 conditions x 2 attacker modes x SEEDS repeats, at each cluster size,
#   then the reconnaissance measurement.
# Outputs: results.csv, recon.csv, recon_messages.log
set -euo pipefail
cd "$(dirname "$0")"

SEEDS="${SEEDS:-1 2 3 4 5}"
SIZES="${SIZES:-100 500}"          # node counts; add 1000 if your machine allows
FEATURES="${FEATURES:-2}"          # affinity features per victim

for N in $SIZES; do
  python3 make_nodes.py --delete || true
  sleep 5
  python3 make_nodes.py --nodes "$N" --seed 42
  sleep 10   # let kwok mark the nodes Ready
  for C in C0 C1 C2 C3; do
    for M in node pod; do
      for S in $SEEDS; do
        echo "=== nodes=$N condition=$C mode=$M seed=$S ==="
        python3 run_experiment.py --condition "$C" --mode "$M" --seed "$S" \
          --affinity-features "$FEATURES" --out results.csv
      done
    done
  done
done

# ---- Reconnaissance channel (Gap 2) on a 100-node cluster with tenant pools ----
python3 make_nodes.py --delete || true
sleep 5
python3 make_nodes.py --nodes 100 --seed 42
sleep 10
NODES=$(kubectl get nodes -l type=kwok -o name | sed 's#node/##')
ATT=$(echo "$NODES" | head -n 20)
SHR=$(echo "$NODES" | tail -n +21)
kubectl label nodes $ATT pool=attacker --overwrite
kubectl label nodes $SHR pool=shared --overwrite
kubectl taint nodes -l pool=attacker pool=attacker:NoSchedule --overwrite
kubectl taint nodes -l pool=shared   pool=shared:NoSchedule   --overwrite

python3 recon_probe.py --out recon.csv                 # admin view
python3 recon_probe.py --as-restricted --out recon.csv # tenant without events access

kubectl taint nodes -l type=kwok pool- || true
kubectl label nodes -l type=kwok pool- || true
echo "Done. See results.csv and recon.csv"
