#!/usr/bin/env bash
export RUST_LOG=warn
OPTS=${OPTS:-"--num-attacks=1000"}
CMD="cargo run --release -- attack $OPTS"

for bits in 5 100 500 1000 1500 2000 2500 2750 2875 3000 3062 3125 3250 3500 4000 5000 6000 7000; do
    echo testing $bits additional bits
    time $CMD --simulated-oracle-mode perfect --additional-bits $bits --stats-file data/additional_bits_$bits.csv
done
exit 0

echo collecting data for idealized oracle
$CMD --stats-file data/ideal.csv --simulated-oracle-mode ideal
echo collecting data for perfect oracle
$CMD --stats-file data/perfect.csv --simulated-oracle-mode perfect
# To also simulate the 0.515 oracle accuracy, add 0.485 to the list below
for noise in 0.1 0.05 0.005; do
    echo collecting data for noise level $noise
    $CMD --simulated-noise $noise --stats-file data/$noise.csv
done
