# Divide and Surrender: HQC Improved PC-Oracle Attack

## Container Usage

Substitute docker for podman if you're using podman.

```sh
docker build -t das .
docker run -it --rm -v "$(realpath data)":/app/data -v "$(realpath figures)":/app/figures das
```

## Reproducing Data & Figures

Simulate the attack for various oracle accuracies. 
For each oracle accuracy it records each attack run's metrics in a CSV in `data/`.
We simulated 1000 attacks per oracle accuracy, but this will take a longer.
We have removed the 0.515 oracle accuracy from the script, as the vast majority of the time will be spent running these attacks.
To enable it again, edit the script.

```sh
OPTS="--num-attacks=50" ./collect_simulation_data.sh
```

Plot the number of oracle calls required during the simulated attacks for each accuracy level.
Outputs a figure in `figures/`

```sh
python visualize/plot.py
```

Run the attack using the SMT oracle
This will almost certainly only work on a Zen2 machine, as some thresholds are fine-tuned for that microarchitecture.
This will also take a few hours. See below for reducing the time needed.
We performed 1000 attacks, but this will take hours.

```sh
RUST_LOG=debug cargo run --release -- --smt --num-attacks=8 --stats-file=data/smt.csv
```

Collects the division throughput data for the current machine for up to 32-bit numerands
It **cannot be run from the container** (unless you give the container read/write access to /sys/devices/system/cpu/smt/control and /sys/bus/event_source/devices/cpu/rdpmc)
***THIS WILL TEMPORARILY DISABLE SMT/HYPERTHREADING ON YOUR MACHINE***

```sh
sudo ./collect_division_throughput_data.sh 
```

## Implementation Tour

- The main attack loop is implemented [here](https://github.com/hqc-attack/divide-and-surrender/blob/7ae02ea1606299160921a9c8f97cf07ce948df0d/src/main.rs#L1287-L1424).
- The PC-Oracle using DIV-SMT is implemented [here](https://github.com/hqc-attack/divide-and-surrender/blob/7ae02ea1606299160921a9c8f97cf07ce948df0d/src/main.rs#L142-L528).
- Zero tester finding is implemented [here](https://github.com/hqc-attack/divide-and-surrender/blob/7ae02ea1606299160921a9c8f97cf07ce948df0d/src/main.rs#L879-L1144).
