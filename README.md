# Divide and Surrender: HQC Improved PC-Oracle Attack

## Container Usage

Substitute docker for podman if you're using podman.

```sh
docker build -t das .
docker run -it --rm -v "$(realpath data)":/app/data -v "$(realpath figures)":/app/figures das
```

### Producing figures

At any point you may run the following command
to produce figures from the collected data.

```sh
python visualize/plot.py
```

The figures will be stored in the `figures` directory.
The script will skip figures for which the data has not yet been collected.
Note that we ship all our collected data


## Reproducing query metrics (Figure 12)

Simulate the attack for various oracle accuracies. 
For each oracle accuracy it records each attack run's metrics in a CSV in `data/`.
We simulated 1000 attacks per oracle accuracy, but this will take a longer.
We have removed the 0.515 oracle accuracy from the script, as the vast majority of the time will be spent running these attacks.
To enable it again, edit the script.

```sh
OPTS="--num-attacks=50" ./collect_simulation_data.sh
```

### DIV-SMT attack (Section 5.2, Requires AMD Zen2)

Run the attack using the SMT oracle
This require an AMD Zen2 processor.

We performed 1000 attacks, but this will take hours.

```sh
RUST_LOG=debug cargo run --release -- attack --smt --num-attacks=8 --stats-file=data/smt.csv
```

To evaluate the results run:

```sh
julia --project=. attack_stats.jl
```

### Figure 9, 10, 11 (Requires AMD Zen2):

Collect oracle accuracy metrics and side-channel timings.
Will also require an AMD Zen2 processor.

We ran this on 100 keys, but this will take days.

```sh
RUST_LOG=debug cargo run --release -- measure --num-keys 2 --dump-accuracy data/accuracy.csv --dump-timings data/timings.csv --max-n-traces 100
```

### Division throughput data (optional)

Collects the division throughput data for the current machine for up to 32-bit numerands.
It **cannot be run from the container** (unless you give the container read/write access to /sys/devices/system/cpu/smt/control and /sys/bus/event_source/devices/cpu/rdpmc).
***THIS WILL TEMPORARILY DISABLE SMT/HYPERTHREADING ON YOUR MACHINE***.

```sh
sudo ./collect_division_throughput_data.sh 
```

## Implementation Tour

- The main attack loop is implemented [here](https://github.com/hqc-attack/divide-and-surrender/blob/7ae02ea1606299160921a9c8f97cf07ce948df0d/src/main.rs#L1287-L1424).
- The PC-Oracle using DIV-SMT is implemented [here](https://github.com/hqc-attack/divide-and-surrender/blob/7ae02ea1606299160921a9c8f97cf07ce948df0d/src/main.rs#L142-L528).
- Zero tester finding is implemented [here](https://github.com/hqc-attack/divide-and-surrender/blob/7ae02ea1606299160921a9c8f97cf07ce948df0d/src/main.rs#L879-L1144).
