# Divide and Surrender: HQC Improved PC-Oracle Attack

This is the artifact submission package for the paper "Divide and Surrender: Exploiting Variable Division Instruction Timing in HQC Key Recovery Attacks" by Robin Leander Schröder, Stefan Gast and Qian Guo. It is to appear in USENIX Security 2024.

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

## Included Dependencies and Changes

### liboqs

The HQC round 4 implementation was added to the `liboqs` library found in `liboqs-rust/oqs-sys/liboqs/src/kem/hqc_r4`.
The implementation is adapted from the [round 4 submission package](https://csrc.nist.gov/csrc/media/Projects/post-quantum-cryptography/documents/round-4/submissions/HQC-Round4.zip) (sha256: `6f5f183c445d925e705dac1fc1a55cb53b3fafa97bd6b5c57339e4bdaca337b3`).
Some utility functions were added. These changes do not modify the attacked cryptosystem itself, but e.g. allow crafting manipulated ciphertexts or eliciting public information.
The implementation was adapted to fit into liboqs. Further, a data-race on a globally used PRNG was fixed.

## System configuration

<details>

<summary>Details about the used hardware and system configuration</summary>

```
$ lsb_release -a
No LSB modules are available.
Distributor ID: Ubuntu
Description:    Ubuntu 20.04.5 LTS
Release:        20.04
Codename:       focal
$ uname -a
Linux lab11 5.18.19-051819-generic #202208211443 SMP PREEMPT_DYNAMIC Fri Feb 24 15:15:07 CET 2023 x86_64 x86_64 x86_64 GNU/Linux
$ cpupower frequency-info 
analyzing CPU 0:
  driver: acpi-cpufreq
  CPUs which run at the same hardware frequency: 0
  CPUs which need to have their frequency coordinated by software: 0
  maximum transition latency:  Cannot determine or is not supported.
  hardware limits: 2.20 GHz - 4.43 GHz
  available frequency steps:  3.60 GHz, 2.80 GHz, 2.20 GHz
  available cpufreq governors: conservative ondemand userspace powersave performance schedutil
  current policy: frequency should be within 2.20 GHz and 3.60 GHz.
                  The governor "ondemand" may decide which speed to use
                  within this range.
  current CPU frequency: Unable to call hardware
  current CPU frequency: 2.20 GHz (asserted by call to kernel)
  boost state support:
    Supported: yes
    Active: no
$ lscpu
Architecture:                    x86_64
CPU op-mode(s):                  32-bit, 64-bit
Byte Order:                      Little Endian
Address sizes:                   43 bits physical, 48 bits virtual
CPU(s):                          16
On-line CPU(s) list:             0-15
Thread(s) per core:              2
Core(s) per socket:              8
Socket(s):                       1
NUMA node(s):                    1
Vendor ID:                       AuthenticAMD
CPU family:                      23
Model:                           113
Model name:                      AMD Ryzen 7 3700X 8-Core Processor
Stepping:                        0
Frequency boost:                 enabled
CPU MHz:                         2200.000
CPU max MHz:                     4426,1709
CPU min MHz:                     2200,0000
BogoMIPS:                        7187.21
Virtualization:                  AMD-V
L1d cache:                       256 KiB
L1i cache:                       256 KiB
L2 cache:                        4 MiB
L3 cache:                        32 MiB
NUMA node0 CPU(s):               0-15
Vulnerability Itlb multihit:     Not affected
Vulnerability L1tf:              Not affected
Vulnerability Mds:               Not affected
Vulnerability Meltdown:          Not affected
Vulnerability Mmio stale data:   Not affected
Vulnerability Retbleed:          Mitigation; untrained return thunk; SMT enabled with STIBP protection
Vulnerability Spec store bypass: Mitigation; Speculative Store Bypass disabled via prctl
Vulnerability Spectre v1:        Mitigation; usercopy/swapgs barriers and __user pointer sanitization
Vulnerability Spectre v2:        Mitigation; Retpolines, IBPB conditional, STIBP always-on, RSB filling, PBRSB-eIBRS Not affected
Vulnerability Srbds:             Not affected
Vulnerability Tsx async abort:   Not affected
Flags:                           fpu vme de pse tsc msr pae mce cx8 apic sep mtrr pge mca cmov pat pse36 clflush mmx fxsr sse sse2 ht syscall nx mmxext fxsr_opt pdpe
                                 1gb rdtscp lm constant_tsc rep_good nopl nonstop_tsc cpuid extd_apicid aperfmperf rapl pni pclmulqdq monitor ssse3 fma cx16 sse4_1 s
                                 se4_2 x2apic movbe popcnt aes xsave avx f16c rdrand lahf_lm cmp_legacy svm extapic cr8_legacy abm sse4a misalignsse 3dnowprefetch os
                                 vw ibs skinit wdt tce topoext perfctr_core perfctr_nb bpext perfctr_llc mwaitx cpb cat_l3 cdp_l3 hw_pstate ssbd mba ibpb stibp vmmca
                                 ll fsgsbase bmi1 avx2 smep bmi2 cqm rdt_a rdseed adx smap clflushopt clwb sha_ni xsaveopt xsavec xgetbv1 xsaves cqm_llc cqm_occup_ll
                                 c cqm_mbm_total cqm_mbm_local clzero irperf xsaveerptr rdpru wbnoinvd arat npt lbrv svm_lock nrip_save tsc_scale vmcb_clean flushbya
                                 sid decodeassists pausefilter pfthreshold avic v_vmsave_vmload vgif v_spec_ctrl umip rdpid overflow_recov succor smca sev sev_es
```

</details>

## Implementation Tour

- The main attack loop is implemented [here](https://github.com/hqc-attack/divide-and-surrender/blob/7ae02ea1606299160921a9c8f97cf07ce948df0d/src/main.rs#L1287-L1424).
- The PC-Oracle using DIV-SMT is implemented [here](https://github.com/hqc-attack/divide-and-surrender/blob/7ae02ea1606299160921a9c8f97cf07ce948df0d/src/main.rs#L142-L528).
- Zero tester finding is implemented [here](https://github.com/hqc-attack/divide-and-surrender/blob/7ae02ea1606299160921a9c8f97cf07ce948df0d/src/main.rs#L879-L1144).
