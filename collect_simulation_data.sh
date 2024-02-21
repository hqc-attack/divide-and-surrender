#!/usr/bin/env bash
export RUST_LOG=info
OPTS=${OPTS:-"--num-attacks=1000"}
CMD="cargo run --release -- $OPTS"
$CMD --stats-file data/ideal.csv --simulated-oracle-mode ideal
$CMD --stats-file data/perfect.csv --simulated-oracle-mode perfect
# To also simulate the 0.515 oracle accuracy, add 0.485 to the list below
for noise in 0.1 0.05 0.005; do
    $CMD --simulated-noise $noise --stats-file data/$noise.csv
done
